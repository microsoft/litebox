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

fn run_x18_fixture(aot: bool) {
    let fixture = Fixture::new();
    let original = elf(X18);
    let code = if aot {
        hook_syscalls_in_elf_with_options(
            &original,
            None,
            RewriteOptions::new(TargetHost::MacOs, false),
        )
        .unwrap()
    } else {
        original
    };
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
fn runtime_x18_gates_preserve_registers_and_branch_targets() {
    run_x18_fixture(false);
}

#[test]
fn aot_x18_gates_preserve_registers_and_branch_targets() {
    run_x18_fixture(true);
}
