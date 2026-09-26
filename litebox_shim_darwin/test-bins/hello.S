/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Writes a greeting with write(2), then returns 0 from main: the loader turns
// the return into exit(0), the way dyld's start glue does.

    .text
    .globl _main
    .p2align 4
_main:
    movl $0x2000004, %eax  // SYS_write
    movl $1, %edi          // stdout
    leaq message(%rip), %rsi
    movl $(message_end - message), %edx
    syscall
    jc 1f
    xorl %eax, %eax
    ret
1:
    movl $1, %eax
    ret

    .section __TEXT,__const
message:
    .ascii "Hello from a Mach-O guest\n"
message_end:
