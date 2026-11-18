/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

# Stand-in for the runner's entry assembly. The kernel maps the rewritten
# text and its footer payload at their declared addresses.
.option norelax
.text
.global _start
_start:
    la gp, block
    la t1, callback
    sd t1, ENTRY(gp)
    la tp, guest_tls
    la a4, output
    la t1, guest
    jalr ra, t1
    li t1, 0x5678
    bne a0, t1, fail
    la t1, block
    bne gp, t1, fail
    ld t1, GUEST_GP(gp)
    bne t1, a3, fail
    la t1, output
    ld t1, 0(t1)
    li t2, 0x0000007300000073
    bne t1, t2, fail
    li a0, 0
    j exit
callback:
    li a0, 172
    bne a7, a0, fail
    li a0, -0x1234
    jr t0
fail:
    li a0, 1
exit:
    li a7, 93
    ecall

.data
.balign 8
block:     .zero BLOCK_SIZE
guest_tls: .dword 0x5678
output:    .dword 0

.section .guest,"ax"
guest: .incbin "text.bin"
.section .gates,"ax"
.incbin "gates.bin"
