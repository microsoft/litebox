// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests for guests whose syscall sites the rewriter redirected.
//!
//! Guests run under `--rewrite-syscalls` with no tar rootfs.

#[allow(dead_code, reason = "shared with the other test binaries")]
mod cache;
#[allow(dead_code, reason = "shared with the other test binaries")]
mod common;

fn run_rewritten_fixture(source: &str, unique_name: &str) -> std::process::Output {
    let target = common::compile(source, unique_name, true, false);
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

    #[cfg(target_os = "linux")]
    let mut command = {
        let broker_path =
            std::path::Path::new(&binary_path).with_file_name("litebox-broker-userland");
        assert!(
            broker_path.is_file(),
            "brokered runner tests require a workspace build producing {}",
            broker_path.display()
        );
        let mut command = std::process::Command::new(broker_path);
        command.arg("--runner").arg(&binary_path);
        command
    };
    #[cfg(not(target_os = "linux"))]
    let mut command = {
        let mut command = std::process::Command::new(binary_path);
        command.arg("--unstable");
        command
    };

    command
        .args(["--rewrite-syscalls"])
        .arg(target)
        .output()
        .expect("Failed to run litebox_runner_linux_userland")
}

#[test]
fn test_host_program_with_rewrite_syscalls() {
    let output = run_rewritten_fixture("./tests/hello.c", "host_program_rewriter");

    assert!(
        output.status.success(),
        "failed to run litebox_runner_linux_userland: {}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{stdout}");
    assert!(stdout.contains("argv[0] = "), "unexpected stdout: {stdout}");
}

/// Linux AArch64 SVC preserves x16/x17 despite their AAPCS veneer role.
/// On non-AArch64 the fixture is a no-op.
#[test]
fn test_svc_scratch_registers_survive_rewritten_syscall() {
    let output = run_rewritten_fixture("./tests/svc_scratch_regs.c", "svc_scratch_regs_rewriter");

    assert!(
        output.status.success(),
        "guest scratch registers did not survive a rewritten syscall ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The synthetic AArch64 restorer must invoke rt_sigreturn, which restores
/// caller-saved registers and sp after the handler returns. Other architectures
/// cover handler entry and return without register checks.
#[test]
fn test_signal_handler_returns_through_sigreturn() {
    let output = run_rewritten_fixture("./tests/sigreturn.c", "sigreturn_rewriter");

    assert!(
        output.status.success(),
        "signal handler did not return cleanly through rt_sigreturn ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("sigreturn ok"),
        "guest did not reach the post-sigreturn write: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

/// An asynchronous resume has no outbound stub, so x16 must survive the direct
/// resume into the handler and the rt_sigreturn resume to the caller.
/// Other architectures cover signal delivery to a busy guest without x16
/// checks.
#[test]
fn test_guest_x16_survives_asynchronous_resume() {
    let output = run_rewritten_fixture("./tests/async_x16.c", "async_x16_rewriter");

    assert!(
        output.status.success(),
        "guest x16 did not survive an asynchronous resume ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("async x16 ok"),
        "guest did not resume after the interruption: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_guest_simd_survives_signal_delivery() {
    let output = run_rewritten_fixture("./tests/sigreturn_simd.c", "sigreturn_simd_rewriter");

    assert!(
        output.status.success(),
        "guest SIMD state did not survive signal delivery ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Semantic stress only: sampling cannot prove a signal PC landed inside a
/// short gate; synthetic tests cover each gate instruction boundary.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_signals_while_exercising_each_aarch64_gate_kind() {
    let output = run_rewritten_fixture("./tests/gate_signals.c", "gate_signals_rewriter");

    assert!(
        output.status.success(),
        "AArch64 gate semantics changed while signals were active ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("gate signals ok"),
        "guest did not finish all gate loops: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn test_x18_virtualization() {
    let target = common::compile(
        "./tests/x18_virtualization.S",
        "x18_virtualization_nolibc",
        true,
        true,
    );
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());
    let output = std::process::Command::new(binary_path)
        .args(["--unstable", "--rewrite-syscalls"])
        .arg(target)
        .output()
        .expect("Failed to run litebox_runner_linux_userland");
    assert!(
        output.status.success(),
        "x18 fixture failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}
