/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Issues a BSD syscall number the shim does not implement and exits with the
// errno it gets back, which must be ENOSYS (78) with the carry flag set; 100
// means the flag was clear.

    .text
    .globl _main
    .p2align 4
_main:
    movl $0x20003e7, %eax  // BSD class, number 999
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
