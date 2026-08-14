// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

.equ __NR_write, 64
.equ __NR_exit, 93
.equ __NR_rt_sigaction, 134
.equ __NR_setitimer, 103
.equ SIGALRM, 14
.equ ITIMER_REAL, 0
.equ REQUIRED_SIGNALS, 512

.text
.align 4
.global _start
.type _start, %function
_start:
    adrp x0, memory
    add x0, x0, :lo12:memory
    bl exercise_x18
    cbnz x0, fail

    ldr x0, [sp]
    cmp x0, #2
    b.ne semantic_ok
    ldr x0, [sp, #16]
    ldrb w0, [x0]
    cmp w0, #'s'
    b.ne fail
    bl run_signal_stress
    cbnz x0, fail
    adrp x1, stress_message
    add x1, x1, :lo12:stress_message
    mov x2, #21
    b write_success

semantic_ok:
    adrp x1, semantic_message
    add x1, x1, :lo12:semantic_message
    mov x2, #22
write_success:
    mov x0, #1
    mov x8, #__NR_write
    svc #0
    mov x0, #0
    mov x8, #__NR_exit
    svc #0
fail:
    // Preserve the exercise status as the process exit code for diagnostics.
    mov x8, #__NR_exit
    svc #0
.size _start, .-_start

.align 4
.type exercise_x18, %function
exercise_x18:
    stp x19, x20, [sp, #-96]!
    stp x14, x15, [sp, #16]
    str x30, [sp, #32]
    mov x20, x0
    movz x16, #0x1616
    movk x16, #0x1616, lsl #16
    movk x16, #0x1616, lsl #32
    movk x16, #0x1616, lsl #48
    movz x17, #0x1717
    movk x17, #0x1717, lsl #16
    movk x17, #0x1717, lsl #32
    movk x17, #0x1717, lsl #48

    // Write, read, and read-write x18.
    movz x0, #0x5678
    movk x0, #0x1234, lsl #16
    mov x18, x0
    mov x1, x18
    cmp x1, x0
    b.ne .Lfail1
    add x18, x18, #8
    add x0, x0, #8
    mov x1, x18
    cmp x1, x0
    b.ne .Lfail2

    // A W-register destination must clear x18's high half.
    movz x0, #0xcdef
    movk x0, #0x89ab, lsl #16
    mov w18, w0
    mov x1, x18
    cmp x1, x0
    b.ne .Lfail3

    // x18 as a memory base and register index.
    mov x18, x20
    mov x2, #0x2222
    str x2, [x18, #8]
    ldr x3, [x18, #8]
    cmp x3, x2
    b.ne .Lfail4
    mov x18, #1
    mov x4, #0x4444
    str x4, [x20, x18, lsl #3]
    ldr x5, [x20, #8]
    cmp x5, x4
    b.ne .Lfail5

    // SP-relative pair operations with x18 as Rt2.
    mov x14, #0x1414
    mov x18, #0x1818
    stp x14, x18, [sp, #48]
    mov x14, xzr
    mov x18, xzr
    ldp x14, x18, [sp, #48]
    mov x2, #0x1414
    cmp x14, x2
    b.ne .Lfail6
    mov x1, x18
    mov x2, #0x1818
    cmp x1, x2
    b.ne .Lfail7

    // NZCV produced by the transformed instruction must remain observable.
    mov x18, #5
    subs x3, x18, #5
    b.ne .Lfail8

    // Read and then write x30 without changing this function's return path.
    mov x19, x30
    mov x18, x30
    mov x1, x18
    cmp x1, x19
    b.ne .Lfail9
    mov x18, x19
    mov x30, x18

    // Explicit x16/x17 operands force an alternate gate scratch pair.
    add x18, x17, x16
    movz x6, #0x1616
    movk x6, #0x1616, lsl #16
    movk x6, #0x1616, lsl #32
    movk x6, #0x1616, lsl #48
    cmp x16, x6
    b.ne .Lfail10
    movz x7, #0x1717
    movk x7, #0x1717, lsl #16
    movk x7, #0x1717, lsl #32
    movk x7, #0x1717, lsl #48
    cmp x17, x7
    b.ne .Lfail11

    // A host transition must preserve the logical x18 and scratch sentinels.
    movz x9, #0x55aa
    movk x9, #0xa55a, lsl #16
    mov x18, x9
    mov x0, #0
    mov x8, #172 // __NR_getpid
    svc #0
    cmp x0, #0
    b.le .Lfail12
    mov x1, x18
    cmp x1, x9
    b.ne .Lfail13
    cmp x16, x6
    b.ne .Lfail14
    cmp x17, x7
    b.ne .Lfail15
    mov x0, xzr
    b .Ldone

.Lfail1: mov x0, #1; b .Ldone
.Lfail2: mov x0, #2; b .Ldone
.Lfail3: mov x0, #3; b .Ldone
.Lfail4: mov x0, #4; b .Ldone
.Lfail5: mov x0, #5; b .Ldone
.Lfail6: mov x0, #6; b .Ldone
.Lfail7: mov x0, #7; b .Ldone
.Lfail8: mov x0, #8; b .Ldone
.Lfail9: mov x0, #9; b .Ldone
.Lfail10: mov x0, #10; b .Ldone
.Lfail11: mov x0, #11; b .Ldone
.Lfail12: mov x0, #12; b .Ldone
.Lfail13: mov x0, #13; b .Ldone
.Lfail14: mov x0, #14; b .Ldone
.Lfail15: mov x0, #15
.Ldone:
    ldr x30, [sp, #32]
    ldp x14, x15, [sp, #16]
    ldp x19, x20, [sp], #96
    ret
.size exercise_x18, .-exercise_x18

.align 4
.type run_signal_stress, %function
run_signal_stress:
    stp x19, x30, [sp, #-16]!
    adrp x1, signal_action
    add x1, x1, :lo12:signal_action
    mov x0, #SIGALRM
    mov x2, xzr
    mov x3, #8
    mov x8, #__NR_rt_sigaction
    svc #0
    cbnz x0, .Lstress_return

    adrp x19, signal_count
    add x19, x19, :lo12:signal_count
    mov x11, xzr
    mov w13, wzr
    movz x9, #0x5678
    movk x9, #0x1234, lsl #16
    mov x18, x9
    movz x16, #0x1616
    movk x16, #0x1616, lsl #16
    movz x17, #0x1717
    movk x17, #0x1717, lsl #16
    mov x14, x16
    mov x15, x17
.Larm_next_signal:
    add w13, w13, #1
    adrp x1, one_shot_timer
    add x1, x1, :lo12:one_shot_timer
    mov x0, #ITIMER_REAL
    mov x2, xzr
    mov x8, #__NR_setitimer
    svc #0
    cbnz x0, .Lstress_return
.Lstress_loop:
    add x18, x18, #1
    add x9, x9, #1
    mov x10, x18
    cmp x10, x9
    b.ne .Lstress_value_fail
    cmp x16, x14
    b.ne .Lstress_scratch_fail
    cmp x17, x15
    b.ne .Lstress_scratch_fail
    add x11, x11, #1
    ldr w12, [x19]
    cmp w12, w13
    b.lo .Lstress_loop
    mov w12, #REQUIRED_SIGNALS
    cmp w13, w12
    b.lo .Larm_next_signal
    cmp x11, #REQUIRED_SIGNALS
    cset x0, lo
    b .Lstress_return
.Lstress_value_fail:
    mov x0, #2
    b .Lstress_return
.Lstress_scratch_fail:
    mov x0, #3
.Lstress_return:
    ldp x19, x30, [sp], #16
    ret
.size run_signal_stress, .-run_signal_stress

.align 4
.type alarm_handler, %function
alarm_handler:
    adrp x9, signal_count
    add x9, x9, :lo12:signal_count
    ldr w10, [x9]
    add w10, w10, #1
    str w10, [x9]
    ret
.size alarm_handler, .-alarm_handler

.section .rodata
semantic_message: .ascii "x18 virtualization ok\n"
stress_message: .ascii "x18 signal stress ok\n"

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
memory: .skip 32
