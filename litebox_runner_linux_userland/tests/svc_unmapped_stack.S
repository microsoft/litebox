/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// The SVC frame is writable on entry, but munmap removes it before return.
// A TLS-restoring outbound stub must not read or restage that guest frame.
.global _start
_start:
    mov x19, sp
    mov x0, #0
    mov x1, #4096
    mov x2, #3
    mov x3, #0x22
    mov x4, #-1
    mov x5, #0
    mov x8, #222 // mmap
    svc #0
    cmp x0, #0
    b.lt fail
    add sp, x0, #4096
    mov x16, #0x1616
    mov x17, #0x1717
    mov x1, #4096
    mov x8, #215 // munmap the stack we are running on
    svc #0
    mov sp, x19
    cbnz x0, fail
    mov x5, #0x1616
    cmp x16, x5
    b.ne fail
    mov x5, #0x1717
    cmp x17, x5
    b.ne fail
    mov x0, #0
    b exit
fail:
    mov sp, x19
    mov x0, #1
exit:
    mov x8, #93
    svc #0
