/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

/*
 * Interrupt Service Routine (ISR) stubs for x86_64
 *
 * This file provides assembly stubs for interrupt handlers that:
 * 1. Save all general-purpose registers in PtRegs layout
 * 2. Call the appropriate Rust handler
 * 3. Restore registers and return via iretq
 *
 * The x86_64 interrupt frame pushed by CPU:
 *   [rsp+40] SS
 *   [rsp+32] RSP
 *   [rsp+24] RFLAGS
 *   [rsp+16] CS
 *   [rsp+8]  RIP
 *   [rsp+0]  Error code (if applicable, otherwise pushed as 0)
 *
 * After push_regs, the stack matches PtRegs layout from litebox_common_linux:
 *   r15, r14, r13, r12, rbp, rbx,     (callee-preserved)
 *   r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi,  (callee-clobbered)
 *   orig_rax (error code),
 *   rip, cs, eflags, rsp, ss          (iret frame)
 */

.code64
.text

/*
 * Macro to save all general-purpose registers onto the stack.
 * This creates a PtRegs-compatible layout for Rust handlers.
 * Push order is reverse of PtRegs struct field order.
 */
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

/*
 * Macro to restore all general-purpose registers from the stack.
 * Pop order matches push_regs (reverse).
 */
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

/*
 * ISR stub for interrupts WITHOUT an error code.
 * The CPU does not push an error code, so we push a dummy 0.
 */
.macro isr_no_err_code name:req handler:req
.global \name
\name:
    cld
    push    0           /* Push dummy error code */
    push_regs
    mov     rdi, rsp    /* Pass pointer to saved registers as first arg */
    call    \handler
    pop_regs
    add     rsp, 8      /* Skip error code */
    iretq
.endm

/*
 * ISR stub for interrupts WITH an error code.
 * The CPU pushes the error code automatically.
 */
.macro isr_with_err_code name:req handler:req
.global \name
\name:
    cld
    push_regs
    mov     rdi, rsp    /* Pass pointer to saved registers as first arg */
    call    \handler
    pop_regs
    add     rsp, 8      /* Skip error code */
    iretq
.endm

/* Exception handlers (vectors 0-31) */

/* Vector 0: Divide Error (#DE) - No error code */
isr_no_err_code isr_divide_error divide_error_handler_impl

/* Vector 3: Breakpoint (#BP) - No error code */
isr_no_err_code isr_breakpoint breakpoint_handler_impl

/* Vector 6: Invalid Opcode (#UD) - No error code */
isr_no_err_code isr_invalid_opcode invalid_opcode_handler_impl

/* Vector 8: Double Fault (#DF) - Error code (always 0) */
isr_with_err_code isr_double_fault double_fault_handler_impl

/* Vector 13: General Protection Fault (#GP) - Error code */
isr_with_err_code isr_general_protection_fault general_protection_fault_handler_impl

/* Vector 14: Page Fault (#PF) - Error code */
isr_with_err_code isr_page_fault page_fault_handler_impl

/* Hypervisor synthetic interrupt handler (vector 0xf3) */
isr_no_err_code isr_hyperv_sint hyperv_sint_handler_impl
