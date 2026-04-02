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
