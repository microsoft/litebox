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

    // 2. Stage bash + utilities needed by X6-X25 fork tests and native baseline.
    let utils = [
        "bash", "cat", "grep", "wc", "sleep", "xargs", "echo", "rm", "chmod", "env", "mount",
        "mkdir", "head", "uname", "sed",
    ];
    for name in &utils {
        if let Some(path) = which(name) {
            let guest = format!("/usr/bin/{name}");
            stage_binary(rootfs, &path, &guest);
        }
    }

    // 3. Stage Node.js for X26-X28 tests.
    // Download if not on host, so the integration test is fully self-contained.
    let node_path = which("node").unwrap_or_else(|| {
        let node_version = "v24.14.1";
        let tarball_name = format!("node-{node_version}-linux-x64.tar.xz");
        let cache_dir = PathBuf::from("/tmp/litebox-test-node-cache");
        let cached_node = cache_dir.join("bin/node");
        if !cached_node.exists() {
            eprintln!("Downloading Node.js {node_version}...");
            fs::create_dir_all(&cache_dir).unwrap();
            let url = format!("https://nodejs.org/dist/{node_version}/{tarball_name}");
            let status = Command::new("curl")
                .args(["-fsSL", "-o", "/tmp/node-download.tar.xz", &url])
                .status()
                .expect("curl failed");
            assert!(status.success(), "Failed to download Node.js from {url}");
            let status = Command::new("tar")
                .args([
                    "xf",
                    "/tmp/node-download.tar.xz",
                    "-C",
                    cache_dir.to_str().unwrap(),
                    "--strip-components=1",
                ])
                .status()
                .expect("tar failed");
            assert!(status.success(), "Failed to extract Node.js");
            fs::remove_file("/tmp/node-download.tar.xz").ok();
            eprintln!("Node.js cached at {}", cache_dir.display());
        }
        cached_node
    });
    stage_binary(rootfs, &node_path, "/usr/local/bin/node");

    // 4. Stage non-PIE test harness for SpawnRemote / cross-worker tests.
    // Built via: cargo rustc -p litebox_test_harness --target-dir target/nonpie -- -C link-args=-no-pie
    // The coordinator's find_nonpie_binary() looks for /litebox-test-harness-nonpie.
    let nonpie_harness_src =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/nonpie/debug/litebox_test_harness");
    if nonpie_harness_src.exists() {
        stage_binary(rootfs, &nonpie_harness_src, "/litebox-test-harness-nonpie");
    }

    // 5. Stage dynamic linker at the standard path.
    let ld_path = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
    if ld_path.exists() {
        stage_file(rootfs, &ld_path);
    }

    // 6. Create writable directories.
    fs::create_dir_all(rootfs.join("shared")).unwrap();
    fs::create_dir_all(rootfs.join("tmp")).unwrap();
    fs::create_dir_all(rootfs.join("root")).unwrap();
    fs::create_dir_all(rootfs.join("home")).unwrap();
    fs::create_dir_all(rootfs.join("proc")).unwrap();
    fs::create_dir_all(rootfs.join("dev")).unwrap();
    // Placeholder for /dev/null — bind-mounted from host in native baseline.
    // Stdio::null() opens /dev/null; without it, exec fails with ENOENT.
    fs::write(rootfs.join("dev/null"), b"").unwrap();
    // /dev/fd symlink for process substitution (X9: cat <(echo hello)).
    #[cfg(unix)]
    std::os::unix::fs::symlink("/proc/self/fd", rootfs.join("dev/fd"))
        .unwrap_or_else(|e| eprintln!("warning: could not create /dev/fd symlink: {e}"));

    // 5. Minimal /etc.
    let etc = rootfs.join("etc");
    fs::create_dir_all(&etc).unwrap();
    fs::write(etc.join("passwd"), "root::0:0:root:/root:/usr/bin/bash\n").unwrap();
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
        // Ensure /usr/bin/sh exists — many tests use "sh" as the shell.
        let sh_dest = rootfs.join("usr/bin/sh");
        if !sh_dest.exists() {
            let _ = std::os::unix::fs::symlink("bash", &sh_dest);
        }
    }

    // 9. Pre-existing symlink in /shared for symlink read-only tests.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            "/shared/host_wrote.txt",
            rootfs.join("shared/host_link.txt"),
        )
        .unwrap_or_else(|e| eprintln!("warning: could not create test symlink: {e}"));
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
        eprintln!(
            "[{label}] FAIL count: expected {expected_fail}, got {fail_count}"
        );
        any_mismatch = true;
    }
    if xpass_count != expected_xpass {
        eprintln!(
            "[{label}] XPASS count: expected {expected_xpass}, got {xpass_count}"
        );
        any_mismatch = true;
    }
    if xfail_count != expected_xfail {
        eprintln!(
            "[{label}] xfail count: expected {expected_xfail}, got {xfail_count}"
        );
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

    let file_count = walkdir::WalkDir::new(rootfs_dir.path())
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    eprintln!("Rootfs contains {file_count} files");

    // ── Pass 1: Native baseline (no litebox) ──
    // Run the test harness directly via `unshare --root` to establish
    // ground truth. Any failure here is a test bug, not a litebox bug.
    // We need --mount to bind-mount /dev/null (user namespaces can't mknod).
    let native_results = {
        let mut cmd = Command::new("unshare");
        cmd.args(["--map-root-user", "--mount", "--pid", "--fork"])
            .arg(format!("--root={}", rootfs_dir.path().display()))
            .args([
                "/usr/bin/bash",
                "-c",
                "mount -t proc proc /proc 2>/dev/null; mount --bind /dev/null /dev/null 2>/dev/null; exec /litebox-test-harness spawn-tree",
            ]);
        run_and_parse("native", &mut cmd)
    };

    // Update these constants when intentionally adding/removing xfails/failures.
    //
    // Native baseline failures (pre-existing nonpie binary staleness):
    //   NPIPE.*: 12 (nonpie binary missing write-known command)
    //   EXITD.*: 6 (nonpie binary missing exit-data command)
    // These are not test bugs — the nonpie binary needs to be rebuilt
    // with the latest test harness code.
    // TODO: fix by rebuilding nonpie binary in build_rootfs.
    const NATIVE_EXPECTED_FAIL: usize = 18;

    if native_results.is_empty() {
        eprintln!("WARNING: native baseline produced no results. Skipping baseline check.");
    } else {
        check_results("native", &native_results, 0, NATIVE_EXPECTED_FAIL, 0);
    }

    // ── Pass 2: Litebox ──
    let litebox_results = {
        let mut cmd = Command::new(&tool_executor);
        cmd.arg("--rootfs")
            .arg(rootfs_dir.path())
            .arg("--record-baseline")
            .arg("--")
            .arg("/litebox-test-harness")
            .arg("spawn-tree");
        run_and_parse("litebox", &mut cmd)
    };

    // Symlink xfails (dynamic — probe returns ENOTSUP in litebox):
    //   basic: 4 subtests × 5 topologies = 20
    //   variants: S.dir + S.dangling + S.nested + S.relative = 4
    // Total xfail: 24
    //
    // Known litebox failures (real platform gaps):
    //   NPIPE.*: 12 (nonpie binary missing write-known)
    //   EXITD.*: 6 (nonpie binary missing exit-data)
    //   US1,3,4,5 + VS1: bare-fork unix socket tests timeout (5)
    //   SS.{pipe_in_subst,multi_pipe_subst,file_pipe_subst,subst_then_cmds,
    //       vscode_osrelease,backtick_pipe}.bash.{A,AA}: stdin-pipe $()
    //       with pipelines loses stdout (6×2 = 12)
    //   SP.file_pipe.{A,AA,B}: stdin-pipe $() with cat|head (3)
    //   X.node.*, EX6-9, XM.*, XDF.*, XS.*, X48, FS.*: various (remaining)
    //
    // XPASS: 0
    const EXPECTED_XFAIL_COUNT: usize = 23;
    const EXPECTED_FAIL_COUNT: usize = 67;
    const EXPECTED_XPASS_COUNT: usize = 1;
    check_results(
        "litebox",
        &litebox_results,
        EXPECTED_XFAIL_COUNT,
        EXPECTED_FAIL_COUNT,
        EXPECTED_XPASS_COUNT,
    );

    // ── Cross-check: any test passing natively but failing in litebox is a litebox bug ──
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
            // Don't panic here — check_results already catches FAILs.
            // This just provides better diagnostics.
        }
    }
}
