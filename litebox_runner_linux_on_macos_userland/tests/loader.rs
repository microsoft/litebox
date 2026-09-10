// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use litebox_syscall_rewriter::{RewriteOptions, TargetHost, hook_syscalls_in_elf_with_options};
use std::{path::Path, process::Command};

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
    let tar = Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .args(["--format=ustar", "-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&root)
        .args(["bin", "lib"])
        .output()
        .unwrap();
    assert!(
        tar.status.success(),
        "{}",
        String::from_utf8_lossy(&tar.stderr)
    );
    let runner = std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_linux_on_macos_userland")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_litebox_runner_linux_on_macos_userland").into());
    for from_tar in [false, true] {
        let mut command = Command::new(&runner);
        command
            .args(["-Z", "--initial-files"])
            .arg(&archive)
            .args(["--env", "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu"]);
        if from_tar {
            command
                .arg("--program-from-tar")
                .arg(format!("/bin/{name}"));
        } else {
            command.arg(root.join("bin").join(name));
        }
        let output = command.output().unwrap();
        // Stdout requires a broker; these tests check successful execution.
        assert_eq!(
            output.status.code(),
            Some(0),
            "{name} (aot={aot}, from_tar={from_tar}): {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn test_load_exec_dynamic() {
    run_program("hello_world_dyn", false);
}

#[test]
fn test_syscall_rewriter() {
    run_program("hello_world_dyn", true);
}
