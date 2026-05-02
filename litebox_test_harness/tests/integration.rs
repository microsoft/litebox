// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration test: runs the test harness inside a Docker container to
//! verify behavior against the native Linux gold standard and litebox.
//!
//! Usage:
//!   cargo test -p litebox_test_harness --test integration              # all passes
//!   cargo test -p litebox_test_harness --test integration test_native  # native only
//!   cargo test -p litebox_test_harness --test integration test_litebox # litebox only
//!   LITEBOX_FILTER=fork cargo test ... --test integration test_native  # filtered
//!
//! The Docker image (`litebox-test`) is built from the multi-target
//! Dockerfile at `litebox_tool_executor/rootfs/Dockerfile`. All rootfs
//! dependencies (bash, coreutils, Node.js, etc.) come from the Dockerfile —
//! never from the host. Test harness and litebox binaries are bind-mounted.
//!
//! Target directory: uses `CARGO_TARGET_DIR` if set, otherwise derives
//! `~/litebox-out/<worktree-basename>` per AGENTS.md convention (ext4 for
//! performance).
//!
//! To add a rootfs dependency, edit the Dockerfile. There is no other path.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Find the workspace root (directory containing Cargo.toml with [workspace]).
fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // litebox_test_harness/Cargo.toml → workspace root is one level up.
    manifest_dir.parent().expect("workspace root").to_path_buf()
}

/// Determine the target directory for builds.
///
/// Uses `CARGO_TARGET_DIR` if set (standard cargo env var), otherwise
/// derives `~/litebox-out/<worktree-basename>` per AGENTS.md convention.
/// This ensures builds land on ext4 (not NTFS) for performance.
fn target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    let ws = workspace_root();
    let name = ws
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(format!("{home}/litebox-out/{name}"))
}

/// Directory containing PIE debug binaries.
fn debug_dir() -> PathBuf {
    target_dir().join("debug")
}

/// Directory containing non-PIE debug binaries.
fn nonpie_dir() -> PathBuf {
    target_dir().join("nonpie/debug")
}

/// Optional spawn-tree filter from `LITEBOX_FILTER` env var.
fn spawn_tree_filter() -> Option<String> {
    std::env::var("LITEBOX_FILTER").ok()
}

/// Build spawn-tree command args, including optional filter.
fn spawn_tree_args() -> Vec<String> {
    let mut args = vec!["spawn-tree".to_string()];
    if let Some(filter) = spawn_tree_filter() {
        args.push(format!("--filter={filter}"));
    }
    args
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
fn run_and_parse(label: &str, command: &mut Command) -> Vec<serde_json::Value> {
    eprintln!("Launching {label}...");
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("failed to launch {label}: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("{stderr}");

    let mut results: Vec<serde_json::Value> = Vec::new();
    for line in stdout.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            results.push(v);
        }
    }
    eprintln!("[{label}] Parsed {} test results", results.len());
    results
}

/// Check test results for unexpected outcomes.
fn check_results(
    label: &str,
    results: &[serde_json::Value],
    expected_xfail: usize,
    expected_fail: usize,
    expected_xpass: usize,
) {
    assert!(
        !results.is_empty(),
        "[{label}] No test results parsed from stdout"
    );

    let fail_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("FAIL"))
        .count();
    let xpass_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("XPASS"))
        .count();
    let xfail_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("xfail"))
        .count();

    let mut any_mismatch = false;
    if fail_count != expected_fail {
        eprintln!("[{label}] FAIL count: expected {expected_fail}, got {fail_count}");
        any_mismatch = true;
    }
    if xpass_count != expected_xpass {
        eprintln!("[{label}] XPASS count: expected {expected_xpass}, got {xpass_count}");
        any_mismatch = true;
    }
    if xfail_count != expected_xfail {
        eprintln!("[{label}] xfail count: expected {expected_xfail}, got {xfail_count}");
        any_mismatch = true;
    }

    if any_mismatch {
        eprintln!("\n=== [{label}] UNEXPECTED RESULTS ===");
        for r in results {
            let result = r["result"].as_str().unwrap_or("");
            if result == "FAIL" || result == "XPASS" {
                eprintln!(
                    "  {} [{}]: {} — {}",
                    r["test"].as_str().unwrap_or("?"),
                    r["agent"].as_str().unwrap_or("?"),
                    result,
                    r["detail"].as_str().unwrap_or(""),
                );
            }
        }
        panic!(
            "[{label}] Result counts don't match expected. \
             FAIL={fail_count}(exp {expected_fail}), \
             XPASS={xpass_count}(exp {expected_xpass}), \
             xfail={xfail_count}(exp {expected_xfail}). \
             If intentional, update the expected counts."
        );
    }

    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in results {
        let result = r["result"].as_str().unwrap_or("unknown");
        *counts.entry(result).or_insert(0) += 1;
    }
    eprintln!(
        "\n=== [{label}] PASSED: {} results ({:?}) ===",
        results.len(),
        counts
    );
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

/// Native baseline: 0 FAIL, 0 xfail, 0 XPASS.
/// This is the gold standard — any failure here is a test or Dockerfile bug.
#[test]
fn test_native() {
    let (_ws_root, debug, nonpie) = setup();

    let args = spawn_tree_args();
    let harness_args: Vec<&str> = std::iter::once("/opt/litebox/litebox_test_harness")
        .chain(args.iter().map(|s| s.as_str()))
        .collect();

    let native_results = {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "--cap-add", "SYS_PTRACE"])
            .arg("-v")
            .arg(format!("{}:/opt/litebox:ro", debug.display()))
            .arg("-v")
            .arg(format!("{}:/opt/nonpie:ro", nonpie.display()))
            .arg("litebox-test")
            .args(&harness_args);
        run_and_parse("native", &mut cmd)
    };

    assert!(
        !native_results.is_empty(),
        "native baseline produced no results"
    );
    check_results("native", &native_results, 0, 0, 0);
}

/// Litebox pass: expected fail/xfail counts must match.
#[test]
fn test_litebox() {
    let (_ws_root, debug, nonpie) = setup();

    let args = spawn_tree_args();
    let mut harness_args: Vec<String> = vec![
        "/opt/litebox/litebox_tool_executor".into(),
        "--rootfs".into(),
        "/".into(),
        "--record-baseline".into(),
        "--".into(),
        "/opt/litebox/litebox_test_harness".into(),
    ];
    harness_args.extend(args);

    let litebox_results = {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "--cap-add", "SYS_PTRACE"])
            .arg("-v")
            .arg(format!("{}:/opt/litebox:ro", debug.display()))
            .arg("-v")
            .arg(format!("{}:/opt/nonpie:ro", nonpie.display()))
            .arg("litebox-test")
            .args(harness_args.iter().map(|s| s.as_str()));
        run_and_parse("litebox", &mut cmd)
    };

    // Update these constants when intentionally adding/removing xfails/failures.
    const EXPECTED_XFAIL_COUNT: usize = 24;
    const EXPECTED_FAIL_COUNT: usize = 46;
    const EXPECTED_XPASS_COUNT: usize = 0;
    check_results(
        "litebox",
        &litebox_results,
        EXPECTED_XFAIL_COUNT,
        EXPECTED_FAIL_COUNT,
        EXPECTED_XPASS_COUNT,
    );
}

/// Host-side tests: TCP port forwarding through the broker.
#[test]
fn test_host_fwd() {
    let (_ws_root, debug, nonpie) = setup();
    run_host_tests(&debug, &nonpie);
}

/// Run host-side tests that exercise TCP port forwarding through the broker.
///
/// Launches litebox inside Docker with:
///   --forward-port 19090:10.0.0.2:9090  (control channel)
///   --forward-port 19091:10.0.0.2:9091  (data test port)
///
/// The guest runs `litebox-test-harness agent-listen 9090`, and the host
/// connects via `localhost:19090` to send commands.
fn run_host_tests(debug: &Path, nonpie: &Path) {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let mut results: Vec<(&str, bool, String)> = Vec::new();

    // Start litebox in Docker with port forwarding + agent-listen mode.
    let container_name = format!("litebox-host-test-{}", std::process::id());
    let mut docker = Command::new("docker");
    docker
        .args(["run", "--rm", "--name", &container_name])
        .args(["--cap-add", "SYS_PTRACE"])
        .args(["-p", "19090:19090", "-p", "19091:19091"])
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
                &"127.0.0.1:19090".parse().unwrap(),
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
                &"127.0.0.1:19091".parse().unwrap(),
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
