/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

.global sandbox_kernel_start;
.global sandbox_kernel_end;
.global sandbox_process_start;
.global _start;
.global _exit;

.macro isr_handler ex:req err=0 handler=int_handler
    .org 0x30 * \ex + 0x200
isr_handler\ex:
    cld
.if  \err
.else
    push    0 /* Dummy error code for this type */
.endif
    call    error_entry
    mov     rdi, rsp
    mov     rsi, \ex    /* Pass the vector as argument */
    mov     rbp, rsp    /* Save original rsp in rbp */
    and     rsp, -16    /* Align stack to 16 bytes */
    call    \handler
    mov     rsp, rbp    /* Restore original rsp */
    jmp     error_return
.endm

    .code64
    .text

.section .head.text,"ax"
_start:
sandbox_kernel_start:
    cld
    cli
    and     rsp, -16                   /* align stack to 16 bytes */
    call    sandbox_kernel_init
1:  /* hlt the machine */
    hlt
    jmp	1b

    .org 0x20
sandbox_process_start:
    and     rsp, -16                   /* align stack to 16 bytes */
    call    sandbox_process_init

1:  /* hlt the machine */
    hlt
    jmp	1b

_exit:
    mov     rsp, gs:0x8
    call    sandbox_task_exit
1:  /* hlt the machine */
    hlt
    jmp	1b

sandbox_tun_read_write_start:
    and    rsp, -16                   /* align stack to 16 bytes */
    call   sandbox_tun_read_write
1:  /* hlt the machine */
    hlt
    jmp	1b

sandbox_mount_start:
sandbox_signal_ret:
rust_begin_unwind:
snp_panic:
    mov     rdi, rsp
    call    sandbox_panic

    .org 0x100
ignore_sysret:
    mov     eax, -38
    sysretq

    .org 0x120
entry_SYSCALL_64:
    swapgs
    mov     gs:0x0, rsp
    mov     rsp, gs:0x8
    push    0x2b        /* pt_regs->ss = __USER_DS */
    push    gs:0x0
    push    r11         /* pt_regs->flags */
    push    0x33        /* pt_regs->cs = __USER_CS */
    push    rcx         /* pt_regs->ip */
    push    rax         /* pt_regs->orig_ax */

    push    rdi         /* pt_regs->di */
    push    rsi         /* pt_regs->si */
    push    rdx         /* pt_regs->dx */
    push    rcx         /* pt_regs->cx */
    push    -38         /* pt_regs->ax = ENOSYS */
    push    r8          /* pt_regs->r8 */
    push    r9          /* pt_regs->r9 */
    push    r10         /* pt_regs->r10 */
    push    r11         /* pt_regs->r11 */
    push    rbx         /* pt_regs->rbx */
    push    rbp         /* pt_regs->rbp */
    push    r12         /* pt_regs->r12 */
    push    r13         /* pt_regs->r13 */
    push    r14         /* pt_regs->r14 */
    push    r15         /* pt_regs->r15 */

    mov     rdi, rsp
    and     rsp, -16    /* align stack to 16 bytes */
    call    do_syscall_64
1:  /* hlt the machine */
    hlt
    jmp	1b

error_entry:
    push	rsi		        /* pt_regs->si */
    mov     rsi, [rsp + 0x8]	/* temporarily store the return address in %rsi */
    mov     [rsp + 0x8], rdi	/* pt_regs->di (overwriting original return address) */
    push    rdx         /* pt_regs->dx */
    push    rcx         /* pt_regs->cx */
    push    rax         /* pt_regs->ax */
    push    r8          /* pt_regs->r8 */
    push    r9          /* pt_regs->r9 */
    push    r10         /* pt_regs->r10 */
    push    r11         /* pt_regs->r11 */
    push    rbx         /* pt_regs->rbx */
    push    rbp         /* pt_regs->rbp */
    push    r12         /* pt_regs->r12 */
    push    r13         /* pt_regs->r13 */
    push    r14         /* pt_regs->r14 */
    push    r15         /* pt_regs->r15 */
    push    rsi         /* return address on top of stack */
    test    BYTE PTR [rsp + 0x90], 0x3  /* check CS */
    jz      1f

    /*
     * We entered from user mode
     */
    swapgs

1:
    ret


error_return:
    test    BYTE PTR [rsp + 0x88], 0x3  /* check CS */
    jz      1f

    /*
     * We entered from user mode
     */
    swapgs

1:
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
    add     rsp, 0x8   /* skip error code */
    iretq

/*
 * IDT Handler
 */
isr_handler 0
isr_handler 1
isr_handler 2
isr_handler 3
isr_handler 4
isr_handler 5
isr_handler 6
isr_handler 7

isr_handler 8 1
isr_handler 9
isr_handler 10 1
isr_handler 11 1
isr_handler 12 1
isr_handler 13 1
isr_handler 14 1 page_fault_handler
isr_handler 15
isr_handler 16 0 floating_point_handler
isr_handler 17 1
isr_handler 18
isr_handler 19
isr_handler 20
/* 21 - 28 */
isr_handler 29 1
isr_handler 30 1
/* 31 - 255 */
isr_handler 31

    .data
.balign 8
/*
 * Keep user's rsp before we switch to use kernel's stack.
 */
rsp_scratch:
    .quad   0

monitor_data_addr:
    .fill   8, 1, 0
.balign	0x1000
stack_guard_page:
    .fill   512, 8, 0
boot_stack:
    .fill   512, 8, 0
    .fill   512, 8, 0
    .fill   512, 8, 0
    .fill   512, 8, 0
boot_stack_end:

sandbox_kernel_end:
