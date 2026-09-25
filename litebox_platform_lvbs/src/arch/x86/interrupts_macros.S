/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

/* Shared entry mechanics for CPU exceptions and platform IRQs.
 * Each global_asm block includes this file before using the macros. The guard
 * also allows LLVM to concatenate multiple blocks into one assembler unit.
 */
.ifndef LITEBOX_X86_INTERRUPT_MACROS_DEFINED
.set LITEBOX_X86_INTERRUPT_MACROS_DEFINED, 1

/* Push order is the reverse of litebox_common_linux::PtRegs. */
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
    push    0
    test    qword ptr [rsp + 16], 0x3
    jnz     .Luser_\name
    push_regs
    mov     rbp, rsp
    and     rsp, -16
    mov     rdi, rbp
    call    \handler
    mov     rsp, rbp
    pop_regs
    add     rsp, 8
    iretq
.Luser_\name:
    push    \vector
    jmp     exception_callback
.endm

.macro isr_with_err_code name:req handler:req vector:req
.global \name
\name:
    cld
    test    qword ptr [rsp + 16], 0x3
    jnz     .Luser_\name
    push_regs
    mov     rbp, rsp
    and     rsp, -16
    mov     rdi, rbp
    call    \handler
    mov     rsp, rbp
    pop_regs
    add     rsp, 8
    iretq
.Luser_\name:
    push    \vector
    jmp     exception_callback
.endm

.endif
