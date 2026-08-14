// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

.equ __NR_write, 64
.equ __NR_exit, 93

.text
.align 4
.global _start
.type _start, %function
_start:
    mov x18, xzr
    cbz w18, 1f
    b fail
1:
    cbnz w18, fail

    mov x18, #1
    cbnz x18, 2f
    b fail
2:
    cbz x18, fail

    mov x18, #2
    tbz w18, #0, 3f
    b fail
3:
    tbnz w18, #0, fail

    mov x18, #1
    lsl x18, x18, #63
    tbnz x18, #63, 4f
    b fail
4:
    tbz x18, #63, fail

    adrp x1, message
    add x1, x1, :lo12:message
    mov x0, #1
    mov x2, #19
    mov x8, #__NR_write
    svc #0
    mov x0, xzr
    b exit
fail:
    mov x0, #1
exit:
    mov x8, #__NR_exit
    svc #0
.size _start, .-_start

.section .rodata
message: .ascii "x18 conditional ok\n"
