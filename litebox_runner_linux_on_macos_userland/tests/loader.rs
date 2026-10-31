// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use litebox_syscall_rewriter::{RewriteOptions, hook_syscalls_in_elf_with_options};
use litebox_trampoline::TargetHost;
use std::{
    path::Path,
    process::{Command, Output},
};

/// Runs prebuilt AArch64 Linux programs with their dynamic loader and glibc through the userland
/// broker and, with `test-broker`, through the in-process test broker.
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
    let runner = common::runner_binary();
    let guest_program = format!("/bin/{name}");
    let output = Command::new(common::broker_binary(&runner))
        .arg("--fs-initial-files")
        .arg(&archive)
        .arg("--runner")
        .arg(&runner)
        .args(["--", "--env", "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu"])
        .arg(&guest_program)
        .output()
        .unwrap();
    assert_guest_output(
        name,
        &format!("{name} (aot={aot}, broker)"),
        &guest_program,
        &output,
    );

    #[cfg(feature = "test-broker")]
    for from_tar in [false, true] {
        let mut command = Command::new(&runner);
        command
            .args(["-Z", "--initial-files"])
            .arg(&archive)
            .args(["--env", "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu"]);
        let expected_argv0 = if from_tar {
            command.arg("--program-from-tar").arg(&guest_program);
            guest_program.clone()
        } else {
            let program = root.join("bin").join(name);
            command.arg(&program);
            program.display().to_string()
        };
        let output = command.output().unwrap();
        assert_guest_output(
            name,
            &format!("{name} (aot={aot}, from_tar={from_tar})"),
            &expected_argv0,
            &output,
        );
    }
}

fn assert_guest_output(name: &str, label: &str, expected_argv0: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label}: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if name == "hello_world_dyn" {
        let expected_prefix = format!(
            "argv[0] = {expected_argv0}\nenvp[0] = LD_LIBRARY_PATH=/lib/aarch64-linux-gnu\nElapsed time: "
        );
        assert!(
            stdout.starts_with(&expected_prefix) && stdout.ends_with(" seconds\n"),
            "{label}: unexpected guest stdout: {stdout:?}"
        );
    } else {
        assert!(
            stdout.ends_with("All threads finished!\n"),
            "{label}: unexpected guest stdout: {stdout:?}"
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
