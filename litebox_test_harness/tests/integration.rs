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
//! Target directory: uses `CARGO_TARGET_DIR` if set, otherwise derives
//! `~/litebox-out/<worktree-basename>` per AGENTS.md convention (ext4).
//!
//! To add a rootfs dependency, edit the Dockerfile. There is no other path.

use std::path::{Path, PathBuf};
use std::process::Command;

use libtest_mimic::{Arguments, Failed, Trial};
use litebox_test_harness::test_registry::TEST_GROUPS;

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let args = Arguments::from_args();
    let mut trials: Vec<Trial> = Vec::new();

    // Each test group becomes two Trials: native::<suite>::<group> and
    // litebox::<suite>::<group>. Each Trial runs its own docker container
    // with `spawn-tree --filter=<suite>.<group>`, so a single group
    // takes ~5s instead of the full battery (~5min).
    //
    // Substring matching works naturally:
    //   cargo test -- native          → all native groups
    //   cargo test -- fork            → all fork groups (both passes)
    //   cargo test -- native::fork    → all native fork groups
    for &(suite, group) in TEST_GROUPS {
        let filter_arg = format!("{suite}.{group}");
        let fa = filter_arg.clone();
        trials.push(Trial::test(
            format!("native::{suite}::{group}"),
            move || run_native_group(&fa),
        ));

        let fa = filter_arg;
        trials.push(Trial::test(
            format!("litebox::{suite}::{group}"),
            move || run_litebox_group(&fa),
        ));
    }

    // Host forwarding trial (not a coordinator suite — uses its own docker run).
    trials.push(Trial::test("host::fwd".to_string(), move || {
        let (_, debug, nonpie) = setup();
        run_host_fwd(&debug, &nonpie);
        Ok(())
    }));

    libtest_mimic::run(&args, trials).exit();
}

// ── Per-suite runners ────────────────────────────────────────────────

/// Native gold standard: run one test group, assert 0 FAIL.
fn run_native_group(filter: &str) -> Result<(), Failed> {
    let (_, debug, nonpie) = setup();
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--cap-add", "SYS_PTRACE"])
        .arg("-v")
        .arg(format!("{}:/opt/litebox:ro", debug.display()))
        .arg("-v")
        .arg(format!("{}:/opt/nonpie:ro", nonpie.display()))
        .arg("litebox-test")
        .args([
            "/opt/litebox/litebox_test_harness",
            "spawn-tree",
            &format!("--filter={filter}"),
        ]);
    let results = run_and_parse(&format!("native::{filter}"), &mut cmd);
    if results.is_empty() {
        return Err(format!("native::{filter} produced no results").into());
    }
    let failures: Vec<_> = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("FAIL"))
        .map(|r| {
            format!(
                "{} [{}]: {}",
                r["test"].as_str().unwrap_or("?"),
                r["agent"].as_str().unwrap_or("?"),
                r["detail"].as_str().unwrap_or(""),
            )
        })
        .collect();
    if !failures.is_empty() {
        return Err(format!(
            "native::{filter}: {} FAIL(s):\n  {}",
            failures.len(),
            failures.join("\n  ")
        )
        .into());
    }
    eprintln!("native::{filter}: {} tests, 0 FAIL", results.len());
    Ok(())
}

/// Litebox pass: run one test group, report results.
fn run_litebox_group(filter: &str) -> Result<(), Failed> {
    let (_, debug, nonpie) = setup();
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--cap-add", "SYS_PTRACE"])
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
            "--",
            "/opt/litebox/litebox_test_harness",
            "spawn-tree",
            &format!("--filter={filter}"),
        ]);
    let results = run_and_parse(&format!("litebox::{filter}"), &mut cmd);
    if results.is_empty() {
        return Err(format!("litebox::{filter} produced no results").into());
    }
    let fail_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("FAIL"))
        .count();
    let xfail_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("xfail"))
        .count();
    let xpass_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("XPASS"))
        .count();
    let pass_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("pass"))
        .count();
    eprintln!(
        "litebox::{filter}: {} tests — {pass_count} pass, {fail_count} FAIL, \
         {xfail_count} xfail, {xpass_count} XPASS",
        results.len(),
    );
    // Don't fail the Trial — litebox has known FAILs/xfails. The Trial
    // reports results; regressions are caught by comparing against
    // the native gold standard.
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
