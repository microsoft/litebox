/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

/* Position-independent, finite test payloads copied into one RX user page.
 * No symbol references outside this blob, no linker relocations inside it.
 * Failures report syscall 0xff; the host QEMU process timeout bounds regressions.
 */
.section .rodata.user_smoke,"a",@progbits
.code64
.global user_smoke_start, user_smoke_end
.global user_smoke_after_syscall, user_smoke_after_breakpoint
.global user_smoke_ud, user_smoke_gp, user_smoke_write, user_smoke_read, user_smoke_nx
user_smoke_start:
    mov ax, cs
    and eax, 3
    cmp eax, 3
    jne .Lfail
    mov edi, {data}
    mov esi, 0x22
    mov edx, 0x33
    mov r8d, 0x88
    mov r9d, 0x99
    mov r10d, 0xaa
    mov rbx, {initial_rbx}
    mov ebp, 0x55
    mov r12d, 0x12
    mov r13d, 0x13
    mov r14d, 0x14
    mov r15d, 0x15
    movdqu xmm0, [rdi]
    movdqu xmm15, [rdi + 16]
    fninit
    fldcw [rdi + 32]
    ldmxcsr [rdi + 36]
    fld1
    push rbx
    pop rax
    cmp rax, rbx
    jne .Lfail

    /* SYSCALL must mask DF in the kernel and restore it on user return. */
    std
    mov eax, 1
    syscall
user_smoke_after_syscall:
    cmp rax, {syscall_reply}
    jne .Lfail
    pushfq
    pop rax
    test eax, 1 << 10
    jz .Lfail
    cld
    mov rax, {updated_rbx}
    cmp rbx, rax
    jne .Lfail
    cmp rbp, 0x55
    jne .Lfail
    cmp r12, 0x12
    jne .Lfail
    cmp r13, 0x13
    jne .Lfail
    cmp r14, 0x14
    jne .Lfail
    cmp r15, 0x15
    jne .Lfail
    cmp rdi, {data}
    jne .Lfail
    cmp rsi, 0x22
    jne .Lfail
    cmp rdx, 0x33
    jne .Lfail
    cmp r8, 0x88
    jne .Lfail
    cmp r9, 0x99
    jne .Lfail
    cmp r10, 0xaa
    jne .Lfail

.macro check_extended_state
    movdqa xmm1, xmm0
    pcmpeqb xmm1, [rdi]
    pmovmskb eax, xmm1
    cmp eax, 0xffff
    jne .Lfail
    movdqa xmm1, xmm15
    pcmpeqb xmm1, [rdi + 16]
    pmovmskb eax, xmm1
    cmp eax, 0xffff
    jne .Lfail
    fnstcw [rdi + 44]
    cmp word ptr [rdi + 44], 0x077f
    jne .Lfail
    stmxcsr [rdi + 40]
    cmp dword ptr [rdi + 40], 0x3f80
    jne .Lfail
    fst qword ptr [rdi + 48]
    mov rax, 0x3ff0000000000000
    cmp [rdi + 48], rax
    jne .Lfail
.endm

    check_extended_state
    mov rax, {breakpoint_rax}
    int3
user_smoke_after_breakpoint:
    cmp rax, {breakpoint_reply}
    jne .Lfail
    check_extended_state
    mov eax, 2
    syscall
    ud2  /* syscall 2 must terminate, not resume */

.Lfail:
    cld
    mov eax, 0xff
    syscall
    ud2

user_smoke_ud:
    ud2
    jmp .Lfail
user_smoke_gp:
    cli
    jmp .Lfail
user_smoke_write:
    mov byte ptr [rdi], 0x90
    jmp .Lfail
user_smoke_read:
    mov rax, [rdi]
    jmp .Lfail
user_smoke_nx:
    jmp rdi
user_smoke_end:
