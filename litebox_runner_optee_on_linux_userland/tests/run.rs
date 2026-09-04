// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;

fn rewrite_binary(input: &str, output: &str) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let status = std::process::Command::new(&cargo)
        .args([
            "run",
            "-p",
            "litebox_syscall_rewriter",
            "--",
            input,
            "-o",
            output,
        ])
        .status()
        .unwrap_or_else(|err| panic!("Failed to run litebox_syscall_rewriter on {input}: {err}"));

    assert!(
        status.success(),
        "litebox_syscall_rewriter failed on {input}: {status}"
    );
}

fn run(name: &str) {
    let runner_path = PathBuf::from(
        std::env::var("NEXTEST_BIN_EXE_litebox_runner_optee_on_linux_userland").unwrap_or_else(
            |_| env!("CARGO_BIN_EXE_litebox_runner_optee_on_linux_userland").to_string(),
        ),
    );
    let broker_path = runner_path.with_file_name("litebox-broker-userland");
    assert!(
        broker_path.is_file(),
        "OP-TEE broker tests require a workspace build producing {}",
        broker_path.display()
    );

    // Create a temporary directory for the hooked binaries
    let temp_dir = std::env::temp_dir().join(format!("litebox_test_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

    let ldelf_input = PathBuf::from("tests/ldelf.elf");
    let ldelf_hooked = temp_dir.join("ldelf.elf.hooked");
    let ta_input = PathBuf::from(format!("tests/{name}.elf"));
    let ta_hooked = temp_dir.join(format!("{name}.elf.hooked"));

    // Generate hooked binaries on the fly
    rewrite_binary(
        ldelf_input.to_str().unwrap(),
        ldelf_hooked.to_str().unwrap(),
    );
    rewrite_binary(ta_input.to_str().unwrap(), ta_hooked.to_str().unwrap());

    let cmds_path = format!("tests/{name}-cmds.json");

    let mut command = std::process::Command::new(&broker_path);
    command.arg("--runner").arg(&runner_path).args([
        ldelf_hooked.to_str().unwrap(),
        ta_hooked.to_str().unwrap(),
        &cmds_path,
    ]);
    println!("Running `{command:?}`");
    let status = command.status().unwrap_or_else(|err| {
        panic!("Failed to run brokered OP-TEE runner against {name}.elf: {err}")
    });

    // Clean up temporary files
    let _ = std::fs::remove_dir_all(&temp_dir);

    assert!(
        status.success(),
        "failed to run brokered OP-TEE runner against {name}.elf: {status}",
    );
}

#[test]
fn test_runner_hello_ta() {
    run("hello-ta");
}

/// Same TA as [`test_runner_hello_ta`], but built with three `PT_LOAD`
/// segments instead of two.
///
/// A third segment produces a middle segment mapped at a *fixed* address with
/// non-zero `pad_end`, which is the case that collides with the LiteBox
/// trampoline pages.
#[test]
fn test_runner_hello_3seg_ta() {
    run("hello3seg-ta");
}

#[test]
fn test_runner_random_ta() {
    run("random-ta");
}

#[test]
fn test_runner_aes_ta() {
    run("aes-ta");
}

#[test]
fn test_runner_kmpp_ta() {
    run("kmpp-ta");
}
