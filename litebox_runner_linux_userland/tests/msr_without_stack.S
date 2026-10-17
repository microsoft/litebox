/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// MSR emulation must not use the guest stack. Save the entry SP in x9 and
// verify TLS read-after-write, XZR, native/virtual x18, and scratch preservation.
.global _start
_start:
    mov x18, #0x1818
    mov x9, sp
    mov x10, #0
    mov sp, x10
    mov x16, #0x1616
    mov x17, #0x1717
    mov x5, #0x1234
    cmp x5, x5
    msr tpidr_el0, x5
    b.ne fail
    b.cc fail
    mrs x6, tpidr_el0
    cmp x5, x6
    b.ne fail
    msr tpidr_el0, x18
    mrs x6, tpidr_el0
    mov x5, #0x1818
    cmp x5, x6
    b.ne fail
    msr tpidr_el0, xzr
    mrs x6, tpidr_el0
    cbnz x6, fail
    mov x5, #0x1616
    cmp x16, x5
    b.ne fail
    mov x5, #0x1717
    cmp x17, x5
    b.ne fail
    mov x0, #0
    b exit
fail:
    mov x0, #1
exit:
    mov sp, x9
    mov x8, #93
    svc #0
