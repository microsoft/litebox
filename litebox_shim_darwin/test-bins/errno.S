/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Opens a path that does not exist. Darwin reports a failed syscall by setting
// the carry flag and returning the errno in rax, so this exits with that errno
// (ENOENT, 2) when the flag is set and with 100 when it is not.

    .text
    .globl _main
    .p2align 4
_main:
    movl $0x2000005, %eax  // SYS_open
    leaq missing(%rip), %rdi
    xorl %esi, %esi         // O_RDONLY
    xorl %edx, %edx
    syscall
    jnc 1f
    movl %eax, %edi
    movl $0x2000001, %eax  // SYS_exit
    syscall
    ud2
1:
    movl $100, %edi
    movl $0x2000001, %eax  // SYS_exit
    syscall
    ud2

    .section __TEXT,__cstring
missing:
    .asciz "/no/such/file"
