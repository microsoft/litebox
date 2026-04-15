// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration test: builds a minimal rootfs, launches litebox, runs the test
//! harness inside, and verifies results.
//!
//! Usage: `cargo test -p litebox_test_harness --test integration`
//!
//! Prerequisites:
//! - `litebox_tool_executor`, `litebox_broker`, and `litebox_runner_linux_userland`
//!   must be built (found via sibling-of-test-binary or LITEBOX_* env vars).
//! - Runs on Linux (WSL2) only — the rootfs is built from the host's glibc.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Discover shared library dependencies of a binary via `ldd`.
fn ldd_deps(binary: &Path) -> Vec<PathBuf> {
    let output = Command::new("ldd")
        .arg(binary)
        .output()
        .expect("ldd failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut deps = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        // Format: "libfoo.so.1 => /lib/x86_64-linux-gnu/libfoo.so.1 (0x...)"
        if let Some(arrow_pos) = line.find("=>") {
            let after = line[arrow_pos + 2..].trim();
            if let Some(space) = after.find(' ') {
                let path = &after[..space];
                if path.starts_with('/') {
                    deps.push(PathBuf::from(path));
                }
            }
        } else if line.starts_with('/') {
            // Format: "/lib64/ld-linux-x86-64.so.2 (0x...)"
            if let Some(space) = line.find(' ') {
                deps.push(PathBuf::from(&line[..space]));
            }
        }
    }
    deps
}

/// Copy a file into the rootfs, preserving its absolute path structure.
fn stage_file(rootfs: &Path, host_path: &Path) {
    let dest = rootfs.join(host_path.strip_prefix("/").unwrap_or(host_path));
    if dest.exists() {
        return;
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    // Follow symlinks — copy the real file.
    let real = fs::canonicalize(host_path).unwrap_or_else(|_| host_path.to_path_buf());
    fs::copy(&real, &dest).expect(&format!("copy {} -> {}", real.display(), dest.display()));
}

/// Stage a binary and all its ldd dependencies into the rootfs.
fn stage_binary(rootfs: &Path, host_path: &Path, guest_path: &str) {
    let dest = rootfs.join(guest_path.strip_prefix('/').unwrap_or(guest_path));
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::copy(host_path, &dest).expect(&format!(
        "copy {} -> {}",
        host_path.display(),
        dest.display()
    ));
    // Make executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms).unwrap();
    }

    // Stage deps.
    for dep in ldd_deps(host_path) {
        stage_file(rootfs, &dep);
    }
}

/// Find a binary on $PATH.
fn which(name: &str) -> Option<PathBuf> {
    let output = Command::new("which").arg(name).output().ok()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Some(fs::canonicalize(&path).unwrap_or_else(|_| PathBuf::from(path)))
    } else {
        None
    }
}

/// Build a minimal rootfs for the test harness.
fn build_rootfs(test_binary: &Path) -> tempfile::TempDir {
    let rootfs_dir = tempfile::tempdir().expect("create temp dir");
    let rootfs = rootfs_dir.path();

    // 1. Stage test harness binary.
    stage_binary(rootfs, test_binary, "/litebox-test-harness");

    // 2. Stage bash + utilities needed by X6-X25 fork tests.
    let utils = ["bash", "cat", "grep", "wc", "sleep", "xargs", "echo", "rm", "chmod"];
    for name in &utils {
        if let Some(path) = which(name) {
            let guest = format!("/usr/bin/{name}");
            stage_binary(rootfs, &path, &guest);
        }
    }

    // 3. Stage Node.js for X26-X28 tests (skip if not installed on host).
    if let Some(node_path) = which("node") {
        stage_binary(rootfs, &node_path, "/usr/local/bin/node");
    }

    // 3. Stage dynamic linker at the standard path.
    let ld_path = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
    if ld_path.exists() {
        stage_file(rootfs, &ld_path);
    }

    // 4. Create writable directories.
    fs::create_dir_all(rootfs.join("shared")).unwrap();
    fs::create_dir_all(rootfs.join("tmp")).unwrap();
    fs::create_dir_all(rootfs.join("root")).unwrap();
    fs::create_dir_all(rootfs.join("home")).unwrap();

    // 5. Minimal /etc.
    let etc = rootfs.join("etc");
    fs::create_dir_all(&etc).unwrap();
    fs::write(
        etc.join("passwd"),
        "root::0:0:root:/root:/usr/bin/bash\n",
    )
    .unwrap();
    fs::write(etc.join("group"), "root:x:0:\n").unwrap();
    fs::write(
        etc.join("nsswitch.conf"),
        "passwd: files\ngroup: files\nhosts: files dns\n",
    )
    .unwrap();

    // 6. Stage libnss_files (required by getpwnam).
    let nss = PathBuf::from("/lib/x86_64-linux-gnu/libnss_files.so.2");
    if nss.exists() {
        stage_file(rootfs, &nss);
    }

    // 7. Host-written test file for F6.
    fs::write(rootfs.join("shared/host_wrote.txt"), "from_host").unwrap();

    // 8. Symlink /bin -> /usr/bin for compatibility.
    #[cfg(unix)]
    {
        let bin = rootfs.join("bin");
        if !bin.exists() {
            std::os::unix::fs::symlink("/usr/bin", &bin).unwrap_or_else(|_| {
                fs::create_dir_all(&bin).unwrap();
                // Fallback: copy bash as /bin/bash.
                if let Some(bash_path) = which("bash") {
                    let _ = fs::copy(&bash_path, bin.join("bash"));
                }
            });
        }
    }

    rootfs_dir
}

/// Find the litebox_tool_executor binary (sibling of test binary or env var).
fn find_tool_executor() -> PathBuf {
    if let Ok(p) = std::env::var("LITEBOX_TOOL_EXECUTOR") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().unwrap().parent().unwrap(); // target/debug/deps -> target/debug
    let candidate = dir.join("litebox_tool_executor");
    if candidate.exists() {
        return candidate;
    }
    panic!(
        "litebox_tool_executor not found. Build it first: cargo build -p litebox_tool_executor\n\
         Or set LITEBOX_TOOL_EXECUTOR env var."
    );
}

#[test]
fn process_tree_tests() {
    let tool_executor = find_tool_executor();
    let test_binary = {
        let exe = std::env::current_exe().expect("current_exe");
        let dir = exe.parent().unwrap().parent().unwrap();
        let candidate = dir.join("litebox_test_harness");
        assert!(
            candidate.exists(),
            "litebox_test_harness binary not found at {}",
            candidate.display()
        );
        candidate
    };

    eprintln!("Building test rootfs...");
    let rootfs_dir = build_rootfs(&test_binary);
    eprintln!("Rootfs at: {}", rootfs_dir.path().display());

    // Count files in rootfs for diagnostics.
    let file_count = walkdir::WalkDir::new(rootfs_dir.path())
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    eprintln!("Rootfs contains {file_count} files");

    eprintln!("Launching litebox with test harness...");
    let output = Command::new(&tool_executor)
        .arg("--rootfs")
        .arg(rootfs_dir.path())
        .arg("/litebox-test-harness")
        .arg("spawn-tree")
        .output()
        .expect("failed to launch tool_executor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("{stderr}");

    // Parse JSON results from stdout.
    let mut results: Vec<serde_json::Value> = Vec::new();
    for line in stdout.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            results.push(v);
        }
    }

    eprintln!("Parsed {} test results", results.len());
    assert!(!results.is_empty(), "No test results parsed from stdout");

    // Check for unexpected failures (FAIL or XPASS).
    let unexpected: Vec<_> = results
        .iter()
        .filter(|r| {
            let result = r["result"].as_str().unwrap_or("");
            result == "FAIL" || result == "XPASS"
        })
        .collect();

    if !unexpected.is_empty() {
        eprintln!("\n=== UNEXPECTED RESULTS ===");
        for r in &unexpected {
            eprintln!(
                "  {} [{}]: {} — {}",
                r["test"].as_str().unwrap_or("?"),
                r["agent"].as_str().unwrap_or("?"),
                r["result"].as_str().unwrap_or("?"),
                r["detail"].as_str().unwrap_or(""),
            );
        }
        panic!(
            "{} unexpected test result(s). See above.",
            unexpected.len()
        );
    }

    // Verify xfail count matches expected. This catches:
    // - Accidental xfail additions (count goes up without updating here)
    // - Fixed xfails that weren't removed (count goes down)
    // Update this constant when intentionally adding/removing xfails.
    const EXPECTED_XFAIL_COUNT: usize = 1; // U6.sibling
    let xfail_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("xfail"))
        .count();
    assert_eq!(
        xfail_count, EXPECTED_XFAIL_COUNT,
        "xfail count changed from {EXPECTED_XFAIL_COUNT} to {xfail_count}. \
         If intentional, update EXPECTED_XFAIL_COUNT in integration.rs."
    );

    // Summary.
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in &results {
        let result = r["result"].as_str().unwrap_or("unknown");
        *counts.entry(result).or_insert(0) += 1;
    }
    eprintln!(
        "\n=== INTEGRATION TEST PASSED: {} results ({:?}) ===",
        results.len(),
        counts
    );
}
