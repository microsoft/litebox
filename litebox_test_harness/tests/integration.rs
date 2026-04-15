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

/// Generate a minimal x86-64 non-PIE ELF binary (ET_EXEC at 0x400000).
///
/// The binary writes "NONPIE_OK\n" to stdout (syscall write) and exits
/// with code 0 (syscall exit). It is statically linked — no libc or
/// dynamic linker needed. This replaces the gcc -no-pie build dependency.
fn generate_nonpie_elf() -> Vec<u8> {
    // Machine code for the program (x86-64):
    //   mov rax, 1          ; syscall: write
    //   mov rdi, 1          ; fd: stdout
    //   lea rsi, [rip+msg]  ; buf: "NONPIE_OK\n"
    //   mov rdx, 10         ; len: 10
    //   syscall
    //   mov rax, 60         ; syscall: exit
    //   xor rdi, rdi        ; code: 0
    //   syscall
    //   msg: "NONPIE_OK\n"
    let code: &[u8] = &[
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
        0x48, 0x8d, 0x35, 0x15, 0x00, 0x00, 0x00, // lea rsi, [rip+21]
        0x48, 0xc7, 0xc2, 0x0a, 0x00, 0x00, 0x00, // mov rdx, 10
        0x0f, 0x05, // syscall
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60
        0x48, 0x31, 0xff, // xor rdi, rdi
        0x0f, 0x05, // syscall
        b'N', b'O', b'N', b'P', b'I', b'E', b'_', b'O', b'K', b'\n',
    ];

    let base_addr: u64 = 0x400000;
    let ehdr_size: u16 = 64; // ELF header size
    let phdr_size: u16 = 56; // Program header size
    let code_offset: u64 = (ehdr_size + phdr_size) as u64;
    let entry: u64 = base_addr + code_offset;
    let file_size = code_offset as usize + code.len();
    let mem_size = file_size; // No BSS needed

    let mut elf = Vec::with_capacity(file_size);

    // ELF header (64 bytes)
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident magic
    elf.push(2); // EI_CLASS: ELFCLASS64
    elf.push(1); // EI_DATA: ELFDATA2LSB
    elf.push(1); // EI_VERSION: EV_CURRENT
    elf.push(0); // EI_OSABI: ELFOSABI_NONE
    elf.extend_from_slice(&[0; 8]); // EI_ABIVERSION + padding
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC (non-PIE!)
    elf.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine: EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&entry.to_le_bytes()); // e_entry
    elf.extend_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no sections)
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&ehdr_size.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&phdr_size.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(elf.len(), ehdr_size as usize);

    // Program header (56 bytes) — single PT_LOAD segment
    elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
    elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset: 0 (load from start)
    elf.extend_from_slice(&base_addr.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&base_addr.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&(file_size as u64).to_le_bytes()); // p_filesz
    elf.extend_from_slice(&(mem_size as u64).to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    assert_eq!(elf.len(), (ehdr_size + phdr_size) as usize);

    // Code + data
    elf.extend_from_slice(code);
    assert_eq!(elf.len(), file_size);

    elf
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
        "mkdir",
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

    // 4. Generate a non-PIE test binary for X40-X42.
    // This is a minimal x86-64 ELF (ET_EXEC, loaded at 0x400000) that
    // writes "NONPIE_OK\n" to stdout and exits. Statically linked — no
    // libc or dynamic linker needed. Replaces the gcc -no-pie dependency.
    let nonpie_bin = rootfs.join("nonpie-echo");
    fs::write(&nonpie_bin, generate_nonpie_elf()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&nonpie_bin, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // 5. Stage dynamic linker at the standard path.
    let ld_path = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
    if ld_path.exists() {
        stage_file(rootfs, &ld_path);
    }

    // 4. Create writable directories.
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
fn check_results(label: &str, results: &[serde_json::Value], expected_xfail: usize) {
    assert!(
        !results.is_empty(),
        "[{label}] No test results parsed from stdout"
    );

    let unexpected: Vec<_> = results
        .iter()
        .filter(|r| {
            let result = r["result"].as_str().unwrap_or("");
            result == "FAIL" || result == "XPASS"
        })
        .collect();

    if !unexpected.is_empty() {
        eprintln!("\n=== [{label}] UNEXPECTED RESULTS ===");
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
            "[{label}] {} unexpected test result(s). See above.",
            unexpected.len()
        );
    }

    let xfail_count = results
        .iter()
        .filter(|r| r["result"].as_str() == Some("xfail"))
        .count();
    assert_eq!(
        xfail_count, expected_xfail,
        "[{label}] xfail count changed from {expected_xfail} to {xfail_count}. \
         If intentional, update the expected count."
    );

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

    if native_results.is_empty() {
        eprintln!("WARNING: native baseline produced no results. Skipping baseline check.");
    } else {
        // Native should have 0 unexpected results (FAIL or XPASS).
        // U6.sibling_connect is xfail (test expects connection failure for litebox)
        // but natively siblings share filesystem so the connect succeeds —
        // the test's pass condition (ConnectFailed) is false, making it xfail.
        // This is expected: the test is designed for litebox's limitation.
        check_results("native", &native_results, 1); // 1 xfail: U6
    }

    // ── Pass 2: Litebox ──
    let litebox_results = {
        let mut cmd = Command::new(&tool_executor);
        cmd.arg("--rootfs")
            .arg(rootfs_dir.path())
            .arg("/litebox-test-harness")
            .arg("spawn-tree");
        run_and_parse("litebox", &mut cmd)
    };

    // Update this constant when intentionally adding/removing xfails.
    const EXPECTED_XFAIL_COUNT: usize = 1; // U6.sibling_connect
    check_results("litebox", &litebox_results, EXPECTED_XFAIL_COUNT);

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
