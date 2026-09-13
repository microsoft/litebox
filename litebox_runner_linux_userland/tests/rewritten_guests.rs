// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests for guests whose syscall sites the rewriter redirected.
//!
//! Guests are rewritten before being loaded into the broker-owned file system.

#[allow(dead_code, reason = "shared with the other test binaries")]
mod cache;
#[allow(dead_code, reason = "shared with the other test binaries")]
mod common;

use common::runner::Runner;

fn run_rewritten_fixture(source: &str, unique_name: &str) -> Vec<u8> {
    let target = common::compile(source, unique_name, true, false);
    Runner::new(&target, unique_name).output()
}

#[test]
fn test_rewritten_program() {
    let output = run_rewritten_fixture("./tests/hello.c", "rewritten_program");
    let stdout = String::from_utf8_lossy(&output);
    println!("{stdout}");
    assert!(stdout.contains("argv[0] = "), "unexpected stdout: {stdout}");
}

/// Linux AArch64 SVC preserves x16/x17 despite their AAPCS veneer role.
/// On non-AArch64 the fixture is a no-op.
#[test]
fn test_svc_scratch_registers_survive_rewritten_syscall() {
    run_rewritten_fixture("./tests/svc_scratch_regs.c", "svc_scratch_regs_rewriter");
}

/// The synthetic AArch64 restorer must invoke rt_sigreturn, which restores
/// caller-saved registers and sp after the handler returns. Other architectures
/// cover handler entry and return without register checks.
#[test]
fn test_signal_handler_returns_through_sigreturn() {
    let output = run_rewritten_fixture("./tests/sigreturn.c", "sigreturn_rewriter");
    assert!(
        String::from_utf8_lossy(&output).contains("sigreturn ok"),
        "guest did not reach the post-sigreturn write: {}",
        String::from_utf8_lossy(&output),
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
        String::from_utf8_lossy(&output).contains("async x16 ok"),
        "guest did not resume after the interruption: {}",
        String::from_utf8_lossy(&output),
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_guest_simd_survives_signal_delivery() {
    run_rewritten_fixture("./tests/sigreturn_simd.c", "sigreturn_simd_rewriter");
}

/// Semantic stress only: sampling cannot prove a signal PC landed inside a
/// short gate; synthetic tests cover each gate instruction boundary.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_signals_while_exercising_each_aarch64_gate_kind() {
    let output = run_rewritten_fixture("./tests/gate_signals.c", "gate_signals_rewriter");
    assert!(
        String::from_utf8_lossy(&output).contains("gate signals ok"),
        "guest did not finish all gate loops: {}",
        String::from_utf8_lossy(&output),
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
    Runner::new(&target, "x18_virtualization_rewriter").run();
}
