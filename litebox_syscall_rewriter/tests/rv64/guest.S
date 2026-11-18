/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

.text
.global _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    c.mv a3, gp
    ld t0, -8(gp)
    c.mv gp, a4
    sd t0, 0(gp)
    c.mv gp, a3
    li a7, 172      # getpid
    ecall
    li t1, 0x1234  # Only the test callback returns this.
    bne a0, t1, failed
    ld t1, -8(gp)
    bne t0, t1, failed
    ld a0, 0(tp)
    ret
failed:
    li a0, -1
    ret
.balign 8
    # Data in executable memory is not code, even when it encodes ecall.
    .dword 0x0000007300000073
__global_pointer$:

    # Non-allocated executable sections are not guest instructions.
.section .offline,"x",@progbits
    lr.d t0, (t1)
