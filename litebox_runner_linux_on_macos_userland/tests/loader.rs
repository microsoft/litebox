// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox_syscall_rewriter::{RewriteOptions, TargetHost, hook_syscalls_in_elf_with_options};
use std::path::Path;

mod common;

// Prebuilt AArch64 Linux programs with their dynamic loader and glibc.
fn run_program(name: &str, aot: bool) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test-bins");
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    for (source, destination) in [
        (name, format!("bin/{name}")),
        ("ld-linux-aarch64.so.1", "lib/ld-linux-aarch64.so.1".into()),
        ("libc.so.6", "lib/aarch64-linux-gnu/libc.so.6".into()),
    ] {
        let path = root.join(destination);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(fixtures.join(source), &path).unwrap();
        if aot {
            let original = std::fs::read(&path).unwrap();
            let rewritten = hook_syscalls_in_elf_with_options(
                &original,
                None,
                RewriteOptions::new(TargetHost::MacOs, true),
            )
            .unwrap_or_else(|error| panic!("rewriting {source}: {error}"));
            std::fs::write(&path, rewritten).unwrap();
        }
    }
    let archive = directory.path().join("root.tar");
    common::archive(&root, &archive);
    // Both former startup paths now resolve through the broker filesystem;
    // the runner must never open the program or archive on the host directly.
    let output = common::run(
        &archive,
        &format!("/bin/{name}"),
        &["--env", "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{name} (aot={aot}): {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if name == "hello_thread" {
        assert!(stdout.contains("Hello from thread"), "{stdout}");
        assert!(stdout.contains("All threads finished!"), "{stdout}");
    } else {
        assert!(
            stdout.contains("argv[0] = /bin/hello_world_dyn"),
            "{stdout}"
        );
        assert!(
            stdout.contains("envp[0] = LD_LIBRARY_PATH=/lib/aarch64-linux-gnu"),
            "{stdout}"
        );
    }
}

#[test]
fn test_load_exec_dynamic() {
    run_program("hello_world_dyn", false);
}

#[test]
fn test_load_exec_dynamic_pthreads() {
    run_program("hello_thread", false);
}

#[test]
fn test_syscall_rewriter() {
    run_program("hello_world_dyn", true);
}

#[test]
fn test_syscall_rewriter_pthreads() {
    run_program("hello_thread", true);
}
