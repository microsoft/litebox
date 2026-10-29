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

/// Asserts that an SVE fixture printed the vector length LiteBox offers and
/// then `success`, or that it found no SVE exactly when LiteBox offers none.
#[cfg(target_arch = "aarch64")]
fn assert_sve_fixture_output(output: &[u8], success: &str) {
    let output = String::from_utf8_lossy(output);
    let expected = match common::guest_sve_vl() {
        Some(vl) => format!("sve vl {}\n{success}\n", vl.bytes()),
        None => "sve unavailable\n".to_owned(),
    };
    assert!(
        output.contains(&expected),
        "expected {expected:?} from the guest: {output}"
    );
}

/// Live SVE state reaches a synchronous signal's `sve_context`, and the
/// handler's edits to the record, FFR included, take effect on return. A
/// second live state in the handler survives a nested synchronous signal whose
/// handler moves its `sve_context` behind an `extra_context`.
/// `AT_MINSIGSTKSZ` is nonzero; see `sve_signal.c`.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_guest_sve_survives_synchronous_signal() {
    let output = run_rewritten_fixture("./tests/sve_signal.c", "sve_signal_rewriter");
    assert_sve_fixture_output(&output, "sve signal ok");
}

/// Live SVE state survives asynchronous interruptions and the guest signal
/// handlers they trigger in two threads that hold different live states at
/// once, each interrupted by a process-directed signal only it unblocks.
/// Each signal also interrupts the threads that block it, among them a third
/// thread with a live state, which resumes without a handler, often at the
/// PC right after its last syscall; see `sve_async.c`.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_guest_sve_survives_asynchronous_interruptions() {
    let output = run_rewritten_fixture("./tests/sve_async.c", "sve_async_rewriter");
    assert_sve_fixture_output(&output, "sve async ok");
}

/// Syscalls keep V0-V31 and discard the rest of the SVE state, also one that
/// LiteBox answers without a host syscall, in both processes of a fork, and
/// across a blocking read that an `SA_RESTART` handler interrupts at its `svc`
/// before it restarts. `PR_SVE_GET_VL` and `PR_SVE_SET_VL` with every valid
/// flag report the vector length, and `PR_SVE_VL_INHERIT` while set, also in a
/// fork child, and `PR_SVE_SET_VL` rejects unknown flag bits; see
/// `sve_syscall_abi.c`.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_guest_sve_syscall_abi() {
    let target = common::compile(
        "./tests/sve_syscall_abi.c",
        "sve_syscall_abi_rewriter",
        true,
        false,
    );
    let output = Runner::new(&target, "sve_syscall_abi_rewriter")
        .allow_process_duplication()
        .output();
    assert_sve_fixture_output(&output, "sve syscall abi ok");
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

/// The same TP-changing guest exercises AOT and runtime-selected rewrite options.
#[test]
#[cfg(target_arch = "aarch64")]
fn test_changed_thread_pointer_survives_intercepted_syscall() {
    let target = common::compile("./tests/native_tp.c", "changed_tp", true, false);
    for runtime in [false, true] {
        let name = if runtime {
            "changed_tp_runtime"
        } else {
            "changed_tp_aot"
        };
        let mut runner = if runtime {
            // Bypass AOT so the unrewritten fixture exercises mmap-time rewriting.
            Runner::new_pre_rewritten(&target, name)
        } else {
            Runner::new(&target, name)
        };
        let output = runner.output();
        assert!(
            String::from_utf8_lossy(&output).contains("native tp ok"),
            "guest did not finish the thread-pointer check: {}",
            String::from_utf8_lossy(&output),
        );
    }
}

/// The JIT page contains only MRS/RET, with no SVC bytes to trigger interception.
#[test]
#[cfg(all(
    target_os = "linux",
    target_arch = "aarch64",
    feature = "aarch64_pacga"
))]
fn test_anonymous_native_tp_access_with_out_of_process_and_embedded_runners() {
    let target = common::compile("./tests/native_tp.c", "native_tp_jit", true, false);
    for embedded in [false, true] {
        let name = if embedded {
            "native_tp_jit_embedded"
        } else {
            "native_tp_jit_external"
        };
        let mut runner = Runner::new(&target, name);
        if embedded {
            runner.use_in_process_runner();
        }
        let output = runner.arg("jit").output();
        assert!(
            String::from_utf8_lossy(&output).contains("native tp ok"),
            "guest did not finish the thread-pointer check: {}",
            String::from_utf8_lossy(&output),
        );
    }
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

/// SVE instructions with x18 operands keep their native results, faults and
/// signal behavior through x18 gates; see `sve_x18.c`.
#[test]
#[cfg(all(target_arch = "aarch64", feature = "aarch64_virtualize_x18"))]
fn test_x18_virtualization_with_sve() {
    let output = run_rewritten_fixture("./tests/sve_x18.c", "sve_x18_rewriter");
    assert_sve_fixture_output(&output, "sve x18 ok");
}
