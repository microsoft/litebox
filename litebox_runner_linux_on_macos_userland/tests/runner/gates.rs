// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_syscall_rewriter::{RewriteOptions, TargetHost, hook_syscalls_in_elf_with_options};

// Exercises TLS, syscalls, x18 spills, SP writeback, and ADR/BLR through x18.
const X18: &[u32] = &[
    0xd2824692, 0xd2822229, 0xd51bd049, 0xd2801588, 0xd4000001, 0xd53bd04a, 0xeb0a013f, 0x54000221,
    0xd282468b, 0xeb0b025f, 0x540001c1, 0xd10043ff, 0xa9002ff2, 0xd2800012, 0xa8c133f2, 0xeb0c025f,
    0x54000101, 0xb40000f2, 0x10000132, 0xd63f0240, 0xf100a81f, 0x54000061, 0xd2800ba8, 0xd4000001,
    0xd2800020, 0xd2800bc8, 0xd4000001, // failure: exit_group(1)
    0xd2800540, 0xd65f03c0, // BLR target: return 42
];

#[test]
fn guest_signal_return_restores_x18_and_vector_state() {
    let fixture = Fixture::new();
    // SIGUSR1 handler clobbers x18 and d0; synthetic rt_sigreturn restores them.
    let code = [
        0xd10083ff, 0x10000409, 0xf90003e9, 0xa900ffff, 0xf9000fff, 0xd2800140, 0x910003e1,
        0xd2800002, 0xd2800103, 0xd28010c8, 0xd4000001, 0xb5000260, 0xd2824692, 0xd28acf09,
        0x9e670120, 0xd2801588, 0xd4000001, 0xd2800141, 0xd2801028, 0xd4000001, 0xd2824689,
        0xeb09025f, 0x54000101, 0x9e66000a, 0xd28acf09, 0xeb09015f, 0x54000081, 0xd2800540,
        0xd2800bc8, 0xd4000001, 0xd2800020, 0xd2800bc8, 0xd4000001, 0xd2933332, 0x9e6703e0,
        0xd65f03c0,
    ];
    std::fs::write(fixture.0.join("program"), elf(&code)).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn current_runtime_rewriter_virtualizes_x18() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("program"), elf(X18)).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn current_aot_rewriter_virtualizes_x18() {
    let fixture = Fixture::new();
    let code = hook_syscalls_in_elf_with_options(
        &elf(X18),
        None,
        RewriteOptions::new(TargetHost::MacOs, true),
    )
    .unwrap();
    std::fs::write(fixture.0.join("program"), code).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn linux_host_tls_gates_are_rejected_on_darwin() {
    let fixture = Fixture::new();
    let code = hook_syscalls_in_elf_with_options(
        &elf(X18),
        None,
        RewriteOptions::new(TargetHost::Linux, true),
    )
    .unwrap();
    std::fs::write(fixture.0.join("program"), code).unwrap();
    let output = fixture.run(&[]);
    assert!(
        output
            .status
            .code()
            .is_some_and(|code| code != 0 && code != 42)
    );
}

#[test]
fn clone_uses_distinct_guest_tls_and_x18_slots() {
    let fixture = Fixture::new();
    // Clone with SETTLS|CHILD_CLEARTID; child changes TP and x18. Parent waits
    // for clear_child_tid, then checks its TP=0x1111 and x18=0x1234 are unchanged.
    let code = [
        0xd2800000, 0xd2a00021, 0xd2800062, 0xd2800443, 0x92800004, 0xd2800005, 0xd2801bc8,
        0xd4000001, 0xf100001f, 0x540006cb, 0xaa0003f3, 0x52800029, 0xb9000a69, 0xd2824692,
        0xd2822229, 0xd51bd049, 0xd281e000, 0xf2a005a0, 0x91404261, 0xd2800002, 0xd2844443,
        0x91002264, 0xd2801b88, 0xd4000001, 0xb40002a0, 0xf100001f, 0x540004ab, 0xd284e214,
        0xd2800f88, 0xd4000001, 0xb9400a69, 0x34000089, 0xf1000694, 0x54ffff61, 0x1400001d,
        0xd53bd049, 0xd282222a, 0xeb0a013f, 0x54000321, 0xd282468a, 0xeb0a025f, 0x540002c1,
        0xd2800540, 0xd2800bc8, 0xd4000001, 0xd53bd049, 0xd284444a, 0xeb0a013f, 0x540001e1,
        0xd282468a, 0xeb0a025f, 0x54000181, 0xd28acf12, 0xd2866669, 0xd51bd049, 0xd2801588,
        0xd4000001, 0xd28acf0a, 0xeb0a025f, 0x54000081, 0xd2800000, 0xd2800ba8, 0xd4000001,
        0xd2800020, 0xd2800bc8, 0xd4000001,
    ];
    std::fs::write(fixture.0.join("program"), elf(&code)).unwrap();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
