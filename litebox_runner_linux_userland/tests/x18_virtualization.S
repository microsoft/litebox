/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

#if defined(__aarch64__)
    .text
    .global _start
_start:
    mov x27, #11
    mov x19, sp
    mov x20, x30
    mov x16, #0x1616
    mov x17, #0x1717

    adr x0, values
    mov x18, x0
    ldr x0, [x18]
    cmp x0, #0x42
    b.ne fail
    mov x1, #8
    ldr x0, [x18, x1]
    cmp x0, #0x43
    b.ne fail
    str x0, [x18]
    ldr x2, [x18]
    cmp x2, x0
    mov x18, x18
    b.ne fail
    cmp sp, x19
    b.ne fail
    cmp x30, x20
    b.ne fail
    mov x0, #0x1616
    cmp x16, x0
    b.ne fail
    mov x0, #0x1717
    cmp x17, x0
    b.ne fail

    mov x18, #5
    mov x0, #7
    cmp x0, x0                    // C = 1
    adc x1, x0, x18
    cmp x1, #13
    b.ne fail
    cmp x0, x0                    // C = 1
    sbc x1, x0, x18
    cmp x1, #2
    b.ne fail
    udiv x1, x0, x18
    cmp x1, #1
    b.ne fail
    mov x0, #-7
    sdiv x1, x0, x18
    cmn x1, #1
    b.ne fail

    mov x27, #14
    adr x18, br_x18_target
    br x18
    b fail
br_x18_target:
    adr x0, br_x18_target
    cmp x18, x0
    b.ne fail
    cmp sp, x19
    b.ne fail
    cmp x30, x20
    b.ne fail
    mov x0, #0x1616
    cmp x16, x0
    b.ne fail
    mov x0, #0x1717
    cmp x17, x0
    b.ne fail

    adr x18, blr_x18_target
    blr x18
blr_x18_return:
    adr x0, blr_x18_return
    cmp x30, x0
    b.ne fail
    b indirect_x18_done
blr_x18_target:
    adr x0, blr_x18_target
    cmp x18, x0
    b.ne fail
    mov x18, x30
    ret x18
indirect_x18_done:
    mov x27, #11
    adr x18, adr_value
    ldr x0, [x18]
    cmp x0, #0x44
    b.ne fail

    mov x18, #0x1234
    movk x18, #0xffff, lsl #48
    mov w18, #0x1234
    mov x0, x18
    mov x1, #0x1234
    cmp x0, x1
    b.ne fail
    movk x18, #0xffff, lsl #48
    add w18, w18, #1
    mov x0, x18
    mov x1, #0x1235
    cmp x0, x1
    b.ne fail

    mov x27, #12
    sub sp, sp, #16
    mov x0, sp
    mov x1, xzr
    mov x8, #59                  // pipe2
    svc #0
    cbnz x0, fail_stack
    ldr w21, [sp]
    ldr w22, [sp, #4]

    mov w0, w22
    adr x1, pipe_byte
    mov x2, #1
    mov x8, #64                  // write
    svc #0
    cmp x0, #1
    b.ne fail_stack
    mov w0, w21
    adr x1, pipe_result
    mov x2, #1
    mov x8, #63                  // read
    svc #0
    cmp x0, #1
    b.ne fail_stack
    adr x0, pipe_result
    ldrb w0, [x0]
    cmp w0, #'X'
    b.ne fail_stack
    add sp, sp, #16

    mov x0, #0x1235
    cmp x18, x0                 // logical x18 survives syscalls
    b.ne fail

    mov x27, #13
    mov x0, #14                 // SIGALRM
    adr x1, sigaction
    mov x2, xzr
    mov x3, #8
    mov x8, #134                // rt_sigaction
    svc #0
    cbnz x0, fail_sigaction
    mov x0, xzr                 // ITIMER_REAL
    adr x1, timer
    mov x2, xzr
    mov x8, #103                // setitimer
    svc #0
    cbnz x0, fail_setitimer

    movz x4, #0x9680
    movk x4, #0x98, lsl #16     // 10,000,000 iterations
1:
    mov x18, x18
    add w18, w18, #0
    ldr w0, signal_count
    cbnz w0, success
    subs x4, x4, #1
    b.ne 1b
    b fail_timeout

signal_handler:
    adr x9, signal_count
    mov w10, #1
    str w10, [x9]
    ret

success:
    mov x0, #0x1235
    cmp x18, x0                 // logical x18 survives signal delivery
    b.ne fail
    mov x0, #1
    adr x1, ok
    mov x2, #7
    mov x8, #64
    svc #0
    mov x0, xzr
    mov x8, #93
    svc #0

fail_stack:
    add sp, sp, #16
fail:
    mov x0, x27
    mov x8, #93
    svc #0
fail_sigaction:
    mov x0, #131
    b fail_exit
fail_setitimer:
    mov x0, #132
    b fail_exit
fail_timeout:
    mov x0, #133
fail_exit:
    mov x8, #93
    svc #0

    .data
    .balign 8
values:
    .quad 0x42, 0x43
adr_value:
    .quad 0x44
pipe_byte:
    .byte 'X'
pipe_result:
    .byte 0
    .balign 8
sigaction:
    .quad signal_handler, 0, 0, 0
timer:
    .quad 0, 0, 0, 1000
signal_count:
    .word 0
ok:
    .ascii "x18 ok\n"
#endif
