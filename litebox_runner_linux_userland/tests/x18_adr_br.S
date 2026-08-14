/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

.equ __NR_write, 64
.equ __NR_exit, 93
.equ __NR_rt_sigaction, 134
.equ __NR_setitimer, 103
.equ SIGALRM, 14
.equ ITIMER_REAL, 0

.text
.align 4
.global _start
.type _start, %function
_start:
    mov x0, #0x1010
    mov x1, #0x1111
    mov x2, #0x1212
    mov x3, #0x1313
    mov x16, #0x1616
    mov x17, #0x1717
    mov x19, #0x1919
    mov x29, sp
    mov x30, #0x3030
    cmp x0, x0
    adr x18, destination
    br x18
    brk #0

destination:
    b.ne fail
    mov x4, #0x1010
    cmp x0, x4
    b.ne fail
    mov x4, #0x1111
    cmp x1, x4
    b.ne fail
    mov x4, #0x1212
    cmp x2, x4
    b.ne fail
    mov x4, #0x1313
    cmp x3, x4
    b.ne fail
    mov x4, #0x1616
    cmp x16, x4
    b.ne fail
    mov x4, #0x1717
    cmp x17, x4
    b.ne fail
    mov x4, #0x1919
    cmp x19, x4
    b.ne fail
    mov x4, sp
    cmp x29, x4
    b.ne fail
    mov x4, #0x3030
    cmp x30, x4
    b.ne fail
    bl run_br_signal_loop
    cbnz x0, fail
    adrp x1, message
    add x1, x1, :lo12:message
    mov x0, #1
    mov x2, #14
    mov x8, #__NR_write
    svc #0
    mov x0, #0
    b exit
fail:
    mov x0, #1
exit:
    mov x8, #__NR_exit
    svc #0
.size _start, .-_start

.align 4
.type run_br_signal_loop, %function
run_br_signal_loop:
    stp x19, x30, [sp, #-16]!
    adrp x1, signal_action
    add x1, x1, :lo12:signal_action
    mov x0, #SIGALRM
    mov x2, xzr
    mov x3, #8
    mov x8, #__NR_rt_sigaction
    svc #0
    cbnz x0, .Lbr_signal_return

    adrp x19, signal_count
    add x19, x19, :lo12:signal_count
    adrp x1, one_shot_timer
    add x1, x1, :lo12:one_shot_timer
    mov x0, #ITIMER_REAL
    mov x2, xzr
    mov x8, #__NR_setitimer
    svc #0
    cbnz x0, .Lbr_signal_return
.Lbr_signal_loop:
    adr x18, .Lbr_signal_target
    br x18
.Lbr_signal_target:
    ldr w9, [x19]
    cbz w9, .Lbr_signal_loop
    mov x0, xzr
.Lbr_signal_return:
    ldp x19, x30, [sp], #16
    ret
.size run_br_signal_loop, .-run_br_signal_loop

.align 4
.type alarm_handler, %function
alarm_handler:
    adrp x9, signal_count
    add x9, x9, :lo12:signal_count
    mov w10, #1
    str w10, [x9]
    ret
.size alarm_handler, .-alarm_handler

.section .rodata
message: .ascii "x18 adr br ok\n"

.data
.align 3
signal_action:
    .quad alarm_handler
    .quad 0
    .quad 0
    .quad 0
one_shot_timer:
    .quad 0, 0
    .quad 0, 100

.bss
.align 3
signal_count: .skip 8
