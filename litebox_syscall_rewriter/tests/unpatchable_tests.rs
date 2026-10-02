// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `tests/lone-syscall`: a static x86-64 ELF whose `.text` is one `syscall`,
//! which leaves no room for a jump to the trampoline. Built with
//! `printf '.globl _start\n.text\n_start:\n  syscall\n' | as -o lone.o &&
//! ld -static -nostdlib -s -o lone-syscall lone.o`.

use litebox_syscall_rewriter::{
    Error, RewriteOptions, UnpatchableSyscalls, hook_syscalls_in_elf, rewrite_binary_reporting,
};

const LONE_SYSCALL: &[u8] = include_bytes!("lone-syscall");

fn entry() -> u64 {
    u64::from_le_bytes(LONE_SYSCALL[24..32].try_into().unwrap())
}

#[test]
fn unpatchable_syscalls_fail_the_rewrite_by_default() {
    assert!(matches!(
        hook_syscalls_in_elf(LONE_SYSCALL, None),
        Err(Error::UnpatchableSyscalls(_))
    ));
}

#[test]
fn unpatchable_syscalls_can_be_kept() {
    let options = RewriteOptions::for_binary(LONE_SYSCALL)
        .with_unpatchable_syscalls(UnpatchableSyscalls::Keep);
    let rewrite = rewrite_binary_reporting(LONE_SYSCALL, None, options).unwrap();
    assert_eq!(rewrite.kept_syscalls, [entry()]);
    // The original image is a prefix of the output, `syscall` included.
    assert_eq!(&rewrite.binary[..LONE_SYSCALL.len()], LONE_SYSCALL);
}
