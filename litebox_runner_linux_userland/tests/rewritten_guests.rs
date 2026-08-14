// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests for guests whose syscall sites the rewriter redirected.
//!
//! Guests run under `--rewrite-syscalls` with no tar rootfs; broker-backed
//! guests live in `run.rs`.

#[allow(dead_code, reason = "shared with the other test binaries")]
mod cache;
#[allow(dead_code, reason = "shared with the other test binaries")]
mod common;

fn run_rewritten_fixture(source: &str, unique_name: &str) -> std::process::Output {
    run_rewritten_fixture_with_args(source, unique_name, &[])
}

fn run_rewritten_fixture_with_args(
    source: &str,
    unique_name: &str,
    guest_args: &[&str],
) -> std::process::Output {
    const GUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let nolibc = std::path::Path::new(source)
        .extension()
        .is_some_and(|extension| extension == "S");
    let target = common::compile(source, unique_name, true, nolibc);
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

    let mut command = std::process::Command::new(binary_path);
    command.args(["--unstable", "--rewrite-syscalls"]);
    let mut child = command
        .arg(target)
        .args(guest_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to run litebox_runner_linux_userland");
    let deadline = std::time::Instant::now() + GUEST_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .expect("failed to poll litebox_runner_linux_userland")
        {
            use std::io::Read as _;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_end(&mut stdout)
                .unwrap();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_end(&mut stderr)
                .unwrap();
            return std::process::Output {
                status,
                stdout,
                stderr,
            };
        }
        if std::time::Instant::now() >= deadline {
            child
                .kill()
                .expect("failed to kill timed-out litebox_runner_linux_userland");
            let output = child
                .wait_with_output()
                .expect("failed to collect timed-out litebox_runner_linux_userland output");
            panic!(
                "litebox_runner_linux_userland exceeded {GUEST_TIMEOUT:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn run_aot_fixture(target: &std::path::Path, guest_args: &[&str]) -> std::process::Output {
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());
    std::process::Command::new(binary_path)
        .env("LITEBOX_LOG", "error")
        .arg(target)
        .args(guest_args)
        .output()
        .expect("failed to run AOT-rewritten guest")
}

#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn prepare_aot_x18_fixture(unique_name: &str) -> std::path::PathBuf {
    let input = common::compile("./tests/x18_virtualization.S", unique_name, true, true);
    let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &std::fs::read(&input).unwrap(),
        None,
        litebox_syscall_rewriter::RewriteOptions::new(
            litebox_syscall_rewriter::TargetHost::Linux,
            true,
        ),
    )
    .unwrap();
    let output_name = common::rewrite_policy_name(unique_name, common::RewritePolicy::CURRENT);
    let output = input.with_file_name(format!("{output_name}_rewritten"));
    std::fs::write(&output, rewritten).unwrap();
    std::fs::set_permissions(&output, std::fs::metadata(&input).unwrap().permissions()).unwrap();
    output
}

#[test]
fn test_host_program_with_rewrite_syscalls() {
    let output = run_rewritten_fixture("./tests/hello.c", "host_program_rewriter");

    assert!(
        output.status.success(),
        "failed to run litebox_runner_linux_userland ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
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
#[ignore = "AArch64 FP/SIMD state is not preserved across guest transitions"]
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
fn test_guest_x18_virtualization() {
    let output =
        run_rewritten_fixture_with_args("./tests/x18_virtualization.S", "x18_virtualization", &[]);

    assert!(
        output.status.success(),
        "x18 guest failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("x18 virtualization ok"),
        "unexpected guest output: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn test_guest_x18_conditional_branches() {
    let output = run_rewritten_fixture("./tests/x18_conditional.S", "x18_conditional");

    assert!(
        output.status.success(),
        "x18 conditional guest failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("x18 conditional ok"),
        "unexpected guest output: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn test_guest_x18_adr_and_terminal_br() {
    let output = run_rewritten_fixture("./tests/x18_adr_br.S", "x18_adr_br");

    assert!(
        output.status.success(),
        "x18 ADR/BR guest failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "x18 adr br ok\n");
}

#[test]
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn test_guest_x18_virtualization_signal_stress() {
    let output = run_rewritten_fixture_with_args(
        "./tests/x18_virtualization.S",
        "x18_virtualization_signal_stress",
        &["stress"],
    );

    assert!(
        output.status.success(),
        "x18 signal stress failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("x18 signal stress ok"),
        "unexpected guest output: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn test_aot_x18_guest_survives_signal_stress() {
    let output_path = prepare_aot_x18_fixture("x18_virtualization_aot_explicit");

    let output = run_aot_fixture(&output_path, &["stress"]);

    assert!(
        output.status.success(),
        "AOT x18 signal stress failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("x18 signal stress ok"),
        "unexpected AOT guest output: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}
