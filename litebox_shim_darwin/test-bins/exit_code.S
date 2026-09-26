/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Exits with status 42 through exit(2) directly, without returning from main.

    .text
    .globl _main
    .p2align 4
_main:
    movl $0x2000001, %eax  // SYS_exit
    movl $42, %edi
    syscall
    ud2
