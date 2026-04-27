// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration test: runs the test harness inside a Docker container to
//! verify behavior against the native Linux gold standard and litebox.
//!
//! Usage: `cargo test -p litebox_test_harness --test integration`
//!
//! The Docker image (`litebox-test`) is built from the multi-target
//! Dockerfile at `litebox_tool_executor/rootfs/Dockerfile`. All rootfs
//! dependencies (bash, coreutils, Node.js, etc.) come from the Dockerfile —
//! never from the host. Test harness and litebox binaries are bind-mounted.
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

/// Find the target/debug directory containing built binaries.
fn debug_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // target/debug/deps/integration-xxx → target/debug
    exe.parent().unwrap().parent().unwrap().to_path_buf()
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

/// Build all required binaries (PIE + non-PIE).
fn ensure_binaries_built(ws_root: &Path) {
    eprintln!("Building litebox binaries (PIE)...");
    let status = Command::new("cargo")
        .current_dir(ws_root)
        .args([
            "build",
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

    eprintln!("Building litebox_test_harness (non-PIE)...");
    let status = Command::new("cargo")
        .current_dir(ws_root)
        .args([
            "rustc",
            "-p",
            "litebox_test_harness",
            "--target-dir",
            "target/nonpie",
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

#[test]
fn process_tree_tests() {
    let ws_root = workspace_root();
    let debug = debug_dir();

    // ── Build everything ──
    ensure_binaries_built(&ws_root);
    ensure_docker_image(&ws_root);

    let harness = debug.join("litebox_test_harness");
    assert!(
        harness.exists(),
        "litebox_test_harness not found at {}",
        harness.display()
    );
    let nonpie = ws_root.join("target/nonpie/debug/litebox_test_harness");
    assert!(
        nonpie.exists(),
        "non-PIE litebox_test_harness not found at {}",
        nonpie.display()
    );

    // ── Pass 1: Native baseline (no litebox, inside Docker) ──
    // The Docker container's filesystem IS the rootfs — immutable.
    // Test harness and non-PIE binaries are bind-mounted read-only.
    let native_results = {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "--cap-add", "SYS_PTRACE"])
            .arg("-v")
            .arg(format!("{}:/opt/litebox:ro", debug.display()))
            .arg("-v")
            .arg(format!(
                "{}:/opt/nonpie:ro",
                ws_root.join("target/nonpie/debug").display()
            ))
            .arg("litebox-test")
            .args(["/opt/litebox/litebox_test_harness", "spawn-tree"]);
        run_and_parse("native", &mut cmd)
    };

    if native_results.is_empty() {
        eprintln!("WARNING: native baseline produced no results.");
    } else {
        // Native baseline must pass everything — 0 FAIL, 0 xfail, 0 XPASS.
        // This is the gold standard: any failure here is a test or Dockerfile bug.
        check_results("native", &native_results, 0, 0, 0);
    }

    // ── Pass 2: Litebox ──
    // Run the test harness inside litebox, inside the same Docker container.
    let litebox_results = {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "--cap-add", "SYS_PTRACE"])
            .arg("-v")
            .arg(format!("{}:/opt/litebox:ro", debug.display()))
            .arg("-v")
            .arg(format!(
                "{}:/opt/nonpie:ro",
                ws_root.join("target/nonpie/debug").display()
            ))
            .arg("litebox-test")
            .args([
                "/opt/litebox/litebox_tool_executor",
                "--rootfs",
                "/",
                "--record-baseline",
                "--",
                "/opt/litebox/litebox_test_harness",
                "spawn-tree",
            ]);
        run_and_parse("litebox", &mut cmd)
    };

    // Update these constants when intentionally adding/removing xfails/failures.
    //
    // Symlink xfails (dynamic — probe returns ENOTSUP in litebox):
    //   basic: 4 subtests × 5 topologies = 20
    //   variants: S.dir + S.dangling + S.nested + S.relative = 4
    // Total xfail: 24
    //
    // Known litebox failures (real platform gaps):
    //   US1,3,4,5 + VS1: bare-fork unix socket tests timeout (5)
    //   XW3,4: cross-worker unix socket connect ECONNREFUSED (2)
    //   SS.{pipe_in_subst,multi_pipe_subst,file_pipe_subst,subst_then_cmds,
    //       vscode_osrelease,backtick_pipe}.{sh,bash}.{A,AA}: stdin-pipe $()
    //       with pipelines loses stdout (6×2×2 = 24)
    //   SP.{pipeline,file_pipe}.{A,AA,B}: stdin-pipe $() with cat|head (6)
    // Total FAIL: 37
    const EXPECTED_XFAIL_COUNT: usize = 24;
    const EXPECTED_FAIL_COUNT: usize = 37;
    const EXPECTED_XPASS_COUNT: usize = 0;
    check_results(
        "litebox",
        &litebox_results,
        EXPECTED_XFAIL_COUNT,
        EXPECTED_FAIL_COUNT,
        EXPECTED_XPASS_COUNT,
    );

    // ── Cross-check: any test passing natively but failing in litebox is a regression ──
    if !native_results.is_empty() {
        let native_pass: std::collections::HashSet<String> = native_results
            .iter()
            .filter(|r| r["result"].as_str() == Some("pass"))
            .filter_map(|r| r["test"].as_str().map(String::from))
            .collect();

        let litebox_fail: Vec<_> = litebox_results
            .iter()
            .filter(|r| r["result"].as_str() == Some("FAIL"))
            .filter(|r| {
                r["test"]
                    .as_str()
                    .map_or(false, |t| native_pass.contains(t))
            })
            .collect();

        if !litebox_fail.is_empty() {
            eprintln!("\n=== LITEBOX REGRESSIONS (pass natively, fail in litebox) ===");
            for r in &litebox_fail {
                eprintln!(
                    "  {} [{}]: {}",
                    r["test"].as_str().unwrap_or("?"),
                    r["agent"].as_str().unwrap_or("?"),
                    r["detail"].as_str().unwrap_or(""),
                );
            }
        }
    }

    // ── Pass 3: Host-side tests (TCP through port forwarding) ──
    // Launches litebox with --forward-port, runs the test harness in
    // agent-listen mode inside the sandbox, and connects from the host
    // via the forwarded port. Tests that the broker's TCP forwarding
    // works end-to-end.
    eprintln!("\n=== Pass 3: Host-side tests ===");
    run_host_tests(&debug, &ws_root);
}

/// Run host-side tests that exercise TCP port forwarding through the broker.
///
/// Launches litebox inside Docker with:
///   --forward-port 19090:10.0.0.2:9090  (control channel)
///   --forward-port 19091:10.0.0.2:9091  (data test port)
///
/// The guest runs `litebox-test-harness agent-listen 9090`, and the host
/// connects via `localhost:19090` to send commands.
fn run_host_tests(debug: &Path, ws_root: &Path) {
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
        .arg(format!(
            "{}:/opt/nonpie:ro",
            ws_root.join("target/nonpie/debug").display()
        ))
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
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok();

    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut writer = stream;

    // Helper: send a command and read the JSON response.
    let send_cmd =
        |w: &mut TcpStream, r: &mut BufReader<TcpStream>, cmd: &str| -> Option<String> {
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
        eprintln!("  {}: H1.control_channel [host] {detail}", if pass { "pass" } else { "FAIL" });
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
            let _ = send_cmd(&mut writer, &mut reader, r#"{"cmd":"net_unlisten","port":9091}"#);
        }
        eprintln!("  {}: H2.data_forward [host] {detail}", if data_pass { "pass" } else { "FAIL" });
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
        eprintln!("  {}: H3.env_get [host] {detail}", if pass { "pass" } else { "FAIL" });
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
