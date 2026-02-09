/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

/*
 * Interrupt Service Routine (ISR) stubs for x86_64
 *
 * Each stub checks the saved CS RPL bits to determine whether the exception
 * came from user mode (ring 3) or kernel mode (ring 0):
 *
 * - User-mode exceptions: push the vector number and jump to
 *   exception_callback (run_thread_arch), which swaps GS, saves the full
 *   CPU context, and routes to the shim's exception handler.
 *
 * - Kernel-mode exceptions: standard push_regs/call/pop_regs/iretq flow
 *   into a per-vector Rust handler.
 *
 * Stacks (Reference: Intel SDM Vol. 3A, §6.12.1):
 *
 * Unless an IST entry is configured for the vector (i.e., #DF in our case),
 * the CPU selects the stack based on the privilege transition:
 *
 * - User-mode (CPL change): the CPU loads RSP from TSS.RSP0. We set a
 *   dedicated per-CPU stack for this (gdt.rs). Since RSP0 is always
 *   reloaded from the TSS, we do not wipe stale data from old exceptions.
 *
 * - Kernel-mode (no CPL change): the CPU continues on the current stack.
 *   The ISR stub pushes registers onto it. Kernel code must ensure enough
 *   stack space before performing operations that might fault; otherwise
 *   the fault handler may overwrite live data or trigger a double fault.
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
 *   rip, cs, rflags, rsp, ss          (iret frame)
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

/* ISR stub for interrupts WITHOUT an error code. */
.macro isr_no_err_code name:req handler:req vector:req
.global \name
\name:
    cld
    push    0                   /* Push dummy error code */
    test    qword ptr [rsp + 16], 0x3  /* Check CS RPL bits */
    jnz     .Luser_\name
    push_regs
    mov     rbp, rsp            /* Save stack pointer */
    and     rsp, -16            /* Align stack to 16 bytes for call */
    mov     rdi, rbp            /* Pass pointer to saved registers as first arg */
    call    \handler
    mov     rsp, rbp            /* Restore stack pointer */
    pop_regs
    add     rsp, 8              /* Skip error code */
    iretq
.Luser_\name:
    push    \vector             /* Pass vector number to exception_callback */
    jmp     exception_callback
.endm

/* ISR stub for interrupts WITH an error code. */
.macro isr_with_err_code name:req handler:req vector:req
.global \name
\name:
    cld
    test    qword ptr [rsp + 16], 0x3  /* Check CS RPL bits */
    jnz     .Luser_\name
    push_regs
    mov     rbp, rsp            /* Save stack pointer */
    and     rsp, -16            /* Align stack to 16 bytes for call */
    mov     rdi, rbp            /* Pass pointer to saved registers as first arg */
    call    \handler
    mov     rsp, rbp            /* Restore stack pointer */
    pop_regs
    add     rsp, 8              /* Skip error code */
    iretq
.Luser_\name:
    push    \vector             /* Pass vector number to exception_callback */
    jmp     exception_callback
.endm

/* Exception handlers (vectors 0-31) */

/* Vector 0: Divide Error (#DE) - No error code */
isr_no_err_code isr_divide_error divide_error_handler_impl 0

/* Vector 1: Debug (#DB) - No error code */
isr_no_err_code isr_debug debug_handler_impl 1

/* Vector 3: Breakpoint (#BP) - No error code */
isr_no_err_code isr_breakpoint breakpoint_handler_impl 3

/* Vector 4: Overflow (#OF) - No error code */
isr_no_err_code isr_overflow overflow_handler_impl 4

/* Vector 5: Bound Range Exceeded (#BR) - No error code */
isr_no_err_code isr_bound_range_exceeded bound_range_exceeded_handler_impl 5

/* Vector 6: Invalid Opcode (#UD) - No error code */
isr_no_err_code isr_invalid_opcode invalid_opcode_handler_impl 6

/* Vector 7: Device Not Available (#NM) - No error code */
isr_no_err_code isr_device_not_available device_not_available_handler_impl 7

/* Vector 8: Double Fault (#DF) - Error code (always 0) */
isr_with_err_code isr_double_fault double_fault_handler_impl 8

/* Vector 12: Stack-Segment Fault (#SS) - Error code */
isr_with_err_code isr_stack_segment_fault stack_segment_fault_handler_impl 12

/* Vector 13: General Protection Fault (#GP) - Error code */
isr_with_err_code isr_general_protection_fault general_protection_fault_handler_impl 13

/* Vector 14: Page Fault (#PF) - Error code */
isr_with_err_code isr_page_fault page_fault_handler_impl 14

/* Vector 16: x87 Floating-Point Exception (#MF) - No error code */
isr_no_err_code isr_x87_floating_point x87_floating_point_handler_impl 16

/* Vector 17: Alignment Check (#AC) - Error code */
isr_with_err_code isr_alignment_check alignment_check_handler_impl 17

/* Vector 19: SIMD Floating-Point Exception (#XM) - No error code */
isr_no_err_code isr_simd_floating_point simd_floating_point_handler_impl 19

/*
 * Hypervisor synthetic interrupt handler (vector 0xf3)
 *
 * This synthetic interrupt is an exception for VTL0 security violations (e.g.,
 * tampering with write-protected MSRs). Hyper-V delivers this exception to VTL1
 * as a SINT.
 *
 * This stub only performs iretq without saving/restoring registers. Since the
 * handler does nothing, registers are naturally preserved. After iretq, the VTL
 * switch loop will save registers and check for synthetic interrupts. VTL1 is
 * not executed concurrently with VTL0, so an immediate iretq is safe.
 */
.global isr_hyperv_sint
isr_hyperv_sint:
    iretq
