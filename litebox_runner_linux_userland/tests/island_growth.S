/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

/* Adapted from the read-only trampoline branch's runtime_growth_dso.S.
   This tests uniform24B islands, not that experiment's ADRP/compact fallback. */
.macro batch name, count
.section .text.\name,"ax",%progbits
.p2align 2
.global \name
.type \name, %function
\name:
.rept \count
    mov x8, #172
    svc #0
    cmp x0, #0
    b.le 1f
.endr
    mov x0, #\count
    ret
1:  mov x0, #-1
    ret
.size \name, .-\name
.endm
batch first, 200
batch second, 201
.section .note.GNU-stack,"",%progbits
