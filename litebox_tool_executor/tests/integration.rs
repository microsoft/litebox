// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration test: run a static Linux ELF binary through the tool executor.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

/// Build a minimal tar archive in memory containing a single file.
fn make_tar(name: &str, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();

    // Tar header: 512 bytes
    let mut header = [0u8; 512];

    // Name field (0..100)
    let name_bytes = name.as_bytes();
    header[..name_bytes.len()].copy_from_slice(name_bytes);

    // Mode (100..108): "0000755\0" (rwxr-xr-x)
    header[100..108].copy_from_slice(b"0000755\0");

    // Owner/group (108..124): "0000000\0" twice
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");

    // Size (124..136): octal, 11 digits + NUL
    let size_str = format!("{:011o}\0", data.len());
    header[124..136].copy_from_slice(size_str.as_bytes());

    // Mtime (136..148): "00000000000\0"
    header[136..148].copy_from_slice(b"00000000000\0");

    // Type flag (156): '0' = regular file
    header[156] = b'0';

    // Checksum (148..156): compute unsigned sum of all header bytes with
    // the checksum field treated as spaces.
    header[148..156].copy_from_slice(b"        ");
    let cksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    let cksum_str = format!("{cksum:06o}\0 ");
    header[148..156].copy_from_slice(cksum_str.as_bytes());

    buf.extend_from_slice(&header);
    buf.extend_from_slice(data);
    // Pad to 512-byte boundary
    let remainder = data.len() % 512;
    if remainder != 0 {
        buf.extend_from_slice(&vec![0u8; 512 - remainder]);
    }
    // End-of-archive: two 512-byte blocks of zeros
    buf.extend_from_slice(&[0u8; 1024]);
    buf
}

#[test]
fn test_execute_static_hello_world() {
    // Read the pre-built static hello-world test binary.
    let bin_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../litebox_runner_linux_on_windows_userland/tests/test-bins/hello_world_static"
    );

    // Rewrite syscalls in the binary.
    let bin_data = std::fs::read(bin_path).expect("Failed to read hello_world_static");
    let hooked = litebox_syscall_rewriter::hook_syscalls_in_elf(&bin_data, None)
        .expect("Failed to rewrite syscalls");

    // Create a tar containing the rewritten binary.
    let tar_data = make_tar("hello_world_static", &hooked);

    // Execute via the tool executor.
    let request = litebox_tool_executor::protocol::ToolRequest {
        command: vec!["/hello_world_static".to_string()],
        env: vec!["PATH=/".to_string()],
        files: std::collections::HashMap::new(),
        timeout_secs: None,
    };

    let result =
        litebox_tool_executor::execute(tar_data, &request, None).expect("execute() failed");

    // The program prints "hello world.\n" and exits with code 0.
    assert_eq!(result.exit_code, 0, "Expected exit code 0");
    assert!(!result.timed_out, "Should not have timed out");
}

/// Helper: get the path to the built executor binary.
fn executor_exe() -> std::path::PathBuf {
    // cargo puts the test binary in target/debug/deps/, the main binary is in target/debug/
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove the test binary name
    if path.ends_with("deps") {
        path.pop(); // remove "deps"
    }
    path.push("litebox_tool_executor.exe");
    path
}

/// Helper: get or create the busybox rootfs tar for process-level tests.
/// Reuses the same rewritten hello_world_static binary in a tar.
fn test_rootfs_tar() -> Vec<u8> {
    let bin_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../litebox_runner_linux_on_windows_userland/tests/test-bins/hello_world_static"
    );
    let bin_data = std::fs::read(bin_path).expect("Failed to read hello_world_static");
    let hooked = litebox_syscall_rewriter::hook_syscalls_in_elf(&bin_data, None)
        .expect("Failed to rewrite syscalls");
    make_tar("hello_world_static", &hooked)
}

/// Process-level test: spawn the executor, run a command, capture stdout.
/// This tests the full pipeline including console mode, stdio passthrough,
/// and process exit code — exactly matching how the VS Code terminal uses it.
#[test]
fn test_process_level_echo() {
    let exe = executor_exe();
    if !exe.exists() {
        eprintln!(
            "Skipping process-level test: executor binary not found at {}",
            exe.display()
        );
        return;
    }

    // Write a temporary tar
    let tar_data = test_rootfs_tar();
    let tar_path = std::env::temp_dir().join("litebox_test_rootfs.tar");
    std::fs::write(&tar_path, &tar_data).unwrap();

    let output = std::process::Command::new(&exe)
        .args([
            "--rootfs",
            tar_path.to_str().unwrap(),
            "/hello_world_static",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("Failed to spawn executor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello world."),
        "Expected 'hello world.' in stdout, got: {stdout}"
    );
    // Verify stdout is clean — no debug "System information" banners.
    assert!(
        !stdout.contains("System information"),
        "stdout should not contain platform debug output, got: {stdout}"
    );
    assert_eq!(output.status.code(), Some(0), "Expected exit code 0");

    std::fs::remove_file(&tar_path).ok();
}

/// Helper: write tar to a temp file, returning the path.
fn write_temp_tar() -> std::path::PathBuf {
    let tar_data = test_rootfs_tar();
    let tar_path = std::env::temp_dir().join("litebox_test_rootfs.tar");
    std::fs::write(&tar_path, &tar_data).unwrap();
    tar_path
}

/// Helper: get the busybox rootfs tar if it exists on disk.
/// Returns None if the rootfs hasn't been built yet (WSL2 prerequisite).
fn busybox_tar_path() -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/busybox-minimal.tar"
    ));
    if path.exists() { Some(path) } else { None }
}

/// Helper: run a command through the executor in direct mode, return stdout.
fn run_direct(tar_path: &std::path::Path, args: &[&str]) -> (String, i32) {
    let exe = executor_exe();
    let mut cmd_args = vec!["--rootfs", tar_path.to_str().unwrap()];
    cmd_args.extend(args);
    let output = std::process::Command::new(&exe)
        .args(&cmd_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("Failed to spawn executor");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, code)
}

/// Direct mode with busybox: simple echo produces output.
#[test]
fn test_direct_echo() {
    let exe = executor_exe();
    if !exe.exists() {
        return;
    }
    let Some(tar_path) = busybox_tar_path() else {
        eprintln!("Skipping: busybox-minimal.tar not found (run prepare-rootfs.sh in WSL2)");
        return;
    };
    let (stdout, _code) = run_direct(&tar_path, &["/bin/busybox", "sh", "-c", "echo hello"]);
    assert!(
        stdout.contains("hello"),
        "Expected 'hello' in stdout, got: {stdout}"
    );
    assert!(
        !stdout.contains("System information"),
        "stdout should not contain debug output, got: {stdout}"
    );
}

/// Direct mode with busybox: double-quoted strings pass through correctly.
#[test]
fn test_direct_quoted_echo() {
    let exe = executor_exe();
    if !exe.exists() {
        return;
    }
    let Some(tar_path) = busybox_tar_path() else {
        return;
    };
    let (stdout, _code) = run_direct(
        &tar_path,
        &["/bin/busybox", "sh", "-c", r#"echo "hello world""#],
    );
    assert!(
        stdout.contains("hello world"),
        "Expected 'hello world' in stdout, got: {stdout}"
    );
}

/// Direct mode with busybox: multiple words without quotes.
#[test]
fn test_direct_echo_multiple_words() {
    let exe = executor_exe();
    if !exe.exists() {
        return;
    }
    let Some(tar_path) = busybox_tar_path() else {
        return;
    };
    let (stdout, _code) = run_direct(
        &tar_path,
        &["/bin/busybox", "sh", "-c", "echo one two three"],
    );
    assert!(
        stdout.contains("one two three"),
        "Expected 'one two three' in stdout, got: {stdout}"
    );
}
