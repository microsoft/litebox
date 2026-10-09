/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

/*
 * Ordinary kernel exceptions need space on the interrupted stack.
 * #DF uses IST1 and NMI uses IST2; neither may depend on that stack.
 *
 * CPU frame: [rsp+40] SS, [rsp+32] RSP, [rsp+24] RFLAGS, [rsp+16] CS,
 * [rsp+8] RIP, [rsp] error code (0 is pushed if the vector has none).
 * After push_regs the stack is a `litebox_common_linux::PtRegs`.
 */

.code64
.text

/* Push order is the reverse of the `PtRegs` field order. */
.macro push_regs
    push    rdi
    push    rsi
    push    rdx
    push    rcx
    push    rax
    push    r8
    push    r9
    push    r10
    push    r11
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
.endm

.macro pop_regs
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rax
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi
.endm

.macro isr_no_err_code name:req handler:req vector:req
.global \name
\name:
    cld
    push    0                   /* No error code; keep the frame uniform */
    test    qword ptr [rsp + 16], 0x3  /* Check CS RPL bits */
    jnz     .Luser_\name
    push_regs
    mov     rbp, rsp
    and     rsp, -16            /* Align stack to 16 bytes for call */
    mov     rdi, rbp            /* &PtRegs */
    call    \handler
    mov     rsp, rbp
    pop_regs
    add     rsp, 8              /* Skip error code */
    iretq
.Luser_\name:
    push    \vector             /* Pass vector number to exception_callback */
    jmp     exception_callback
.endm

.macro isr_with_err_code name:req handler:req vector:req
.global \name
\name:
    cld
    test    qword ptr [rsp + 16], 0x3  /* Check CS RPL bits */
    jnz     .Luser_\name
    push_regs
    mov     rbp, rsp
    and     rsp, -16            /* Align stack to 16 bytes for call */
    mov     rdi, rbp            /* &PtRegs */
    call    \handler
    mov     rsp, rbp
    pop_regs
    add     rsp, 8              /* Skip error code */
    iretq
.Luser_\name:
    push    \vector             /* Pass vector number to exception_callback */
    jmp     exception_callback
.endm

isr_no_err_code isr_divide_error divide_error_handler_impl 0

isr_no_err_code isr_debug debug_handler_impl 1

isr_no_err_code isr_breakpoint breakpoint_handler_impl 3

isr_no_err_code isr_overflow overflow_handler_impl 4

isr_no_err_code isr_bound_range_exceeded bound_range_exceeded_handler_impl 5

isr_no_err_code isr_invalid_opcode invalid_opcode_handler_impl 6

isr_no_err_code isr_device_not_available device_not_available_handler_impl 7

/* #DF is a kernel failure regardless of the interrupted privilege level. */
.global isr_double_fault
isr_double_fault:
    cld
    push_regs
    mov     rbp, rsp
    and     rsp, -16
    mov     rdi, rbp            /* &PtRegs */
    call    double_fault_handler_impl
    ud2

isr_with_err_code isr_stack_segment_fault stack_segment_fault_handler_impl 12

isr_with_err_code isr_general_protection_fault general_protection_fault_handler_impl 13

/* Kernel user-copy faults may need the shim's demand paging. */
.global isr_page_fault
isr_page_fault:
    cld
    test    qword ptr [rsp + 16], 0x3  /* Check CS RPL bits */
    push    14                  /* Pass vector number (push does not affect flags) */
    jnz     .Luser_isr_page_fault
    jmp     kernel_exception_callback
.Luser_isr_page_fault:
    jmp     exception_callback

isr_no_err_code isr_x87_floating_point x87_floating_point_handler_impl 16

isr_with_err_code isr_alignment_check alignment_check_handler_impl 17

isr_no_err_code isr_simd_floating_point simd_floating_point_handler_impl 19

/* NMI entry must not depend on GS or acquire locks. */
.global isr_ignore
isr_ignore:
    iretq

/*
 * External interrupts (vectors 32..=255), handled by the registered handler
 * or fatal. IDT entries require an 8-byte stride; CALL pushes stub + 5 for
 * vector lookup.
 *
 * They arrive from user mode, or from the kernel only while it halts with
 * IF=1. Entry does not depend on GS (which may still be the user's): the
 * handler must not touch per-CPU data, so no SWAPGS. The kernel runs with
 * SSE disabled, so only the caller-saved GPRs need saving.
 */
.balign 8
.global isr_external_stubs
isr_external_stubs:
.rept 224
    .balign 8
    call    isr_external
.endr

isr_external:
    cld
    clac                        /* SMAP stays enforced; IRETQ restores AC */
    /* [rsp] stub return address, [rsp+8] RIP, [rsp+16] CS */
    push    rax
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    rbp
    mov     rbp, rsp
    mov     rdi, [rbp + 80]     /* stub return address */
    lea     rax, [rip + isr_external_stubs + 5]
    sub     rdi, rax
    shr     rdi, 3
    add     rdi, 32             /* vector */
    mov     rsi, [rbp + 88]     /* interrupted RIP */
    mov     rdx, [rbp + 96]     /* interrupted CS */
    and     rsp, -16
    call    external_interrupt_handler_impl
    mov     rsp, rbp
    pop     rbp
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rax
    add     rsp, 8              /* stub return address */
    iretq
