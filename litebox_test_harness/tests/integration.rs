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
//!   cargo test -p litebox_test_harness --test integration                          # all
//!   cargo test -p litebox_test_harness --test integration -- native                # all native
//!   cargo test -p litebox_test_harness --test integration -- native::fork          # native fork groups
//!   cargo test -p litebox_test_harness --test integration -- native::fork::capture_pipe  # one group
//!   cargo test -p litebox_test_harness --test integration -- fork                  # fork in both passes
//!   cargo test -p litebox_test_harness --test integration -- --list                # list all trials
//!
//! Target directory: uses `CARGO_TARGET_DIR` if set, otherwise `target/`.
//!
//! To add a rootfs dependency, edit the Dockerfile. There is no other path.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use libtest_mimic::{Arguments, Failed, Trial};

// ── Pass result cache ────────────────────────────────────────────────
//
// One docker run per pass (native/litebox). The docker run executes
// spawn-tree with `--filter=suite1,suite2,...` for only the suites
// that have matching Trials. Results are cached so all Trials in the
// same pass share one docker run.

/// Cached test IDs from collect_all_tests (direct library call, no subprocess).
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

static PASS_CACHE: Mutex<Option<std::collections::HashMap<String, Vec<serde_json::Value>>>> =
    Mutex::new(None);

/// Get (or compute) results for a pass. Runs docker once per pass.

/// Whether to keep docker containers after exit (for debugging).
fn keep_containers() -> bool {
    std::env::var("LITEBOX_KEEP_CONTAINER").is_ok()
}

/// Docker run args: --rm unless LITEBOX_KEEP_CONTAINER is set.
fn docker_run_args() -> Vec<&'static str> {
    if keep_containers() {
        vec!["run", "--cap-add", "SYS_PTRACE"]
    } else {
        vec!["run", "--rm", "--cap-add", "SYS_PTRACE"]
    }
}

fn get_pass_results(pass: &str, filter_arg: &str) -> Vec<serde_json::Value> {
    let mut cache = PASS_CACHE.lock().unwrap();
    let map = cache.get_or_insert_with(std::collections::HashMap::new);
    if let Some(results) = map.get(pass) {
        return results.clone();
    }

    let (_, debug, nonpie) = setup();

    let mut spawn_args: Vec<String> = vec!["spawn-tree".into()];
    if !filter_arg.is_empty() {
        spawn_args.push(format!("--filter={filter_arg}"));
    }

    let mut results = match pass {
        "native" => {
            let mut cmd = Command::new("docker");
            cmd.args(docker_run_args())
                .arg("-v")
                .arg(format!("{}:/opt/litebox:ro", debug.display()))
                .arg("-v")
                .arg(format!("{}:/opt/nonpie:ro", nonpie.display()))
                .arg("litebox-test")
                .arg("/opt/litebox/litebox_test_harness")
                .args(&spawn_args);
            run_and_parse(&format!("native[{filter_arg}]"), &mut cmd)
        }
        "litebox" => {
            let mut cmd = Command::new("docker");
            cmd.args(docker_run_args())
                .arg("-v")
                .arg(format!("{}:/opt/litebox:ro", debug.display()))
                .arg("-v")
                .arg(format!("{}:/opt/nonpie:ro", nonpie.display()))
                .arg("litebox-test")
                .args(["timeout", "--signal=KILL", "1200"])
                .args([
                    "/opt/litebox/litebox_tool_executor",
                    "--rootfs",
                    "/",
                    "--record-baseline",
                    "--",
                    "/opt/litebox/litebox_test_harness",
                ])
                .args(&spawn_args);
            run_and_parse(&format!("litebox[{filter_arg}]"), &mut cmd)
        }
        _ => panic!("unknown pass: {pass}"),
    };

    // Fill in missing test IDs from the native baseline so litebox
    // reports the same test count as native. This runs on the host
    // (not inside docker) so it's not affected by container timeouts.
    if !results.is_empty() {
        let recorded_ids: std::collections::HashSet<String> = results
            .iter()
            .filter_map(|r| r["test"].as_str().map(String::from))
            .collect();

        let all_ids = get_test_ids();
        let mut filled = 0usize;
        for test_id in all_ids {
            if !recorded_ids.contains(test_id.as_str()) {
                results.push(serde_json::json!({
                    "test": test_id,
                    "agent": "?",
                    "result": "FAIL",
                    "detail": "not executed",
                }));
                filled += 1;
            }
        }
        if filled > 0 {
            eprintln!("[{pass}] filled {filled} unexecuted test IDs as FAIL");
        }
    }

    // Drift check: parse TEST_IDS from stderr and compare against baseline.
    // Warn if registered IDs don't match the baseline file.
    let test_ids = get_test_ids();
    let baseline_ids: std::collections::HashSet<&str> =
        test_ids.iter().map(|s| s.as_str()).collect();
    let registered_ids: std::collections::HashSet<String> = results
        .iter()
        .filter(|r| {
            r["detail"]
                .as_str()
                .map_or(true, |d| !d.starts_with("not executed"))
        })
        .filter_map(|r| r["test"].as_str().map(String::from))
        .collect();
    let extra: Vec<_> = registered_ids
        .iter()
        .filter(|id| !baseline_ids.contains(id.as_str()))
        .collect();
    if !extra.is_empty() {
        eprintln!(
            "[{pass}] DRIFT: {} test IDs not in registered test IDs (new tests added?):",
            extra.len()
        );
        for id in extra.iter().take(10) {
            eprintln!("  + {id}");
        }
    }

    map.insert(pass.to_string(), results.clone());
    results
}

/// Determine which suites are needed based on the cargo test filter.
/// Returns comma-separated suite names, or empty string for all suites.
/// Compute the --filter argument for spawn-tree from the cargo test filter.
///
/// The cargo test filter matches Trial names like:
///   "native::matrix::netlink::NL1.netlink_socket"
///
/// We extract the part after the pass prefix (native::/litebox::) and
/// pass it to the coordinator, which handles:
///   "matrix" (suite), "matrix.netlink" (group), "NL1" (test ID prefix)
fn compute_suite_filter(cargo_filter: &str) -> String {
    if cargo_filter.is_empty() {
        return String::new();
    }

    // Strip pass prefix if present.
    // Strip pass prefix if present.
    let filter = cargo_filter
        .strip_prefix("native::")
        .or_else(|| cargo_filter.strip_prefix("litebox::"))
        .unwrap_or(cargo_filter);

    // If the filter is just the pass name or empty, run all.
    if filter.is_empty() || filter == "native" || filter == "litebox" {
        return String::new();
    }

    // If it looks like a suite::group::testid, convert :: to . for coordinator.
    // "matrix::netlink::NL1" → "NL1" (test ID takes precedence)
    // "matrix::netlink" → "matrix.netlink" (group filter)
    // "matrix" → "matrix" (suite filter)
    // "NL1" → "NL1" (test ID filter)
    let parts: Vec<&str> = filter.split("::").collect();
    match parts.len() {
        3 => parts[2].to_string(),                 // suite::group::testid → testid
        2 => format!("{}.{}", parts[0], parts[1]), // suite::group → suite.group
        1 => parts[0].to_string(),                 // suite or testid
        _ => filter.to_string(),
    }
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let args = Arguments::from_args();

    // Compute which suites are needed based on the cargo test filter.
    // This determines the --filter= argument for docker run.
    let cargo_filter = args.filter.as_deref().unwrap_or("");
    let suite_filter = compute_suite_filter(cargo_filter);
    if !suite_filter.is_empty() {
        eprintln!("[integration] suite filter: {suite_filter}");
    }

    let mut trials: Vec<Trial> = Vec::new();

    // Generate one Trial per test ID from the harness binary's list-ids.
    // No docker needed — just calls register_*() functions.
    let test_ids = get_test_ids();
    for tid in test_ids.iter().cloned() {
        let sf = suite_filter.clone();
        let tid2 = tid.clone();
        trials.push(Trial::test(format!("native::{tid}"), move || {
            run_pass_group("native", &sf, &tid2)
        }));

        let sf = suite_filter.clone();
        let tid2 = tid.clone();
        trials.push(Trial::test(format!("litebox::{tid}"), move || {
            run_pass_group("litebox", &sf, &tid2)
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

// ── Per-group runners (backed by pass cache) ─────────────────────────

/// Native gold standard: get pass results from cache, assert 0 FAIL.
/// Validate a single test ID from cached pass results.
fn run_pass_group(pass: &str, suite_filter: &str, test_id: &str) -> Result<(), Failed> {
    let results = get_pass_results(pass, suite_filter);
    if results.is_empty() {
        return Err(format!("{pass} produced no results").into());
    }
    let matching: Vec<_> = results
        .iter()
        .filter(|r| r["test"].as_str() == Some(test_id))
        .collect();
    if matching.is_empty() {
        return Err(format!("{pass}::{test_id}: not found in results").into());
    }
    for r in &matching {
        let result = r["result"].as_str().unwrap_or("?");
        if result == "FAIL" {
            let detail = r["detail"].as_str().unwrap_or("");
            return Err(format!("{pass}::{test_id}: {detail}").into());
        }
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

/// Run the test harness and parse JSON results from stdout.
/// Falls back to parsing coordinator eprintln output from stderr
/// when running under litebox (litebox_tool_executor doesn't forward
/// guest stdout).
fn run_and_parse(label: &str, command: &mut Command) -> Vec<serde_json::Value> {
    eprintln!("Launching {label}...");
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("failed to launch {label}: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("{stderr}");

    // Try JSON from stdout first (native runs).
    let mut results: Vec<serde_json::Value> = Vec::new();
    for line in stdout.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            results.push(v);
        }
    }

    // Fallback: parse coordinator eprintln output from stderr (litebox runs).
    // Lines look like: "  pass: TEST_ID [AGENT] DETAIL"
    //                  "  FAIL: TEST_ID [AGENT] DETAIL"
    //                  "  xfail: TEST_ID [AGENT] DETAIL"
    if results.is_empty() {
        for line in stderr.lines() {
            let line = line.trim();
            let (result, rest) = if let Some(r) = line.strip_prefix("pass: ") {
                ("pass", r)
            } else if let Some(r) = line.strip_prefix("FAIL: ") {
                ("FAIL", r)
            } else if let Some(r) = line.strip_prefix("xfail: ") {
                ("xfail", r)
            } else if let Some(r) = line.strip_prefix("XPASS: ") {
                ("XPASS", r)
            } else {
                continue;
            };
            // Parse "TEST_ID [AGENT] DETAIL"
            let (test, agent) = if let Some(bracket) = rest.find('[') {
                let test = rest[..bracket].trim();
                let agent_end = rest[bracket..].find(']').unwrap_or(rest.len() - bracket);
                let agent = &rest[bracket + 1..bracket + agent_end];
                (test, agent)
            } else {
                (rest, "?")
            };
            results.push(serde_json::json!({
                "test": test,
                "agent": agent,
                "result": result,
            }));
        }
    }

    eprintln!("[{label}] Parsed {} test results", results.len());
    results
}

/// Shared setup: build binaries and Docker image, return paths.
fn setup() -> (PathBuf, PathBuf, PathBuf) {
    let ws_root = workspace_root();
    let debug = debug_dir();
    let nonpie = nonpie_dir();

    ensure_binaries_built(&ws_root);
    ensure_docker_image(&ws_root);

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
}

/// Run host-side tests that exercise TCP port forwarding through the broker.
///
/// Launches litebox inside Docker with:
///   --forward-port 19090:10.0.0.2:9090  (control channel)
///   --forward-port 19091:10.0.0.2:9091  (data test port)
///
/// The guest runs `litebox-test-harness agent-listen 9090`, and the host
/// connects via `localhost:19090` to send commands.
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

    // Wait for the TCP agent to be ready by retrying connections.
    let stream = {
        let mut attempts = 0;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            match TcpStream::connect_timeout(
                &format!("127.0.0.1:{ctrl_port}").parse().unwrap(),
                Duration::from_secs(2),
            ) {
                Ok(s) => {
                    eprintln!("[host-test] Connected to TCP agent after {attempts} retries");
                    break s;
                }
                Err(e) => {
                    attempts += 1;
                    if attempts > 30 {
                        // Capture stderr for diagnostics.
                        let _ = Command::new("docker")
                            .args(["kill", &container_name])
                            .status();
                        let _ = child.wait();
                        panic!("[host-test] Could not connect to TCP agent after 15s: {e}");
                    }
                }
            }
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut writer = stream;

    // Helper: send a command and read the JSON response.
    let send_cmd = |w: &mut TcpStream, r: &mut BufReader<TcpStream>, cmd: &str| -> Option<String> {
        let msg = format!("{cmd}\n");
        w.write_all(msg.as_bytes()).ok()?;
        w.flush().ok()?;
        let mut line = String::new();
        r.read_line(&mut line).ok()?;
        Some(line.trim().to_string())
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
