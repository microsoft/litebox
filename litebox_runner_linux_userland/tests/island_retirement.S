/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Exactly one SVC, in the last word of the page removed by the test. The
// continuation has no rewritten sites and stays mapped through callback return.
.section .text.site,"ax",%progbits
.global retirement_entry
.type retirement_entry, %function
retirement_entry:
    stp x29, x30, [sp, #-16]!
    mov x14, sp
    mov x8, x3
    mov x16, #0x1616
    mov x17, #0x1717
    mov x30, #0x3030
    movi v0.16b, #0xa5
    mov x6, #0xa0000000
    msr nzcv, x6
    mov w7, #1
    stlr w7, [x4]
    b .Lsvc
.org 4092
.Lsvc:
    svc #0
.section .text.continuation,"ax",%progbits
    stp x0, x16, [x5, #0]
    stp x17, x30, [x5, #16]
    mrs x6, nzcv
    mov x7, sp
    stp x6, x7, [x5, #32]
    str q0, [x5, #48]
    str x14, [x5, #64]
    ldp x29, x30, [sp], #16
    ret
.section .note.GNU-stack,"",%progbits
