/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

/* PVH entry: paging off, protected mode, flat segments, EBX=start_info.
 * Based on kvm_poc_v2. All 32-bit addresses are absolute constants; no dynamic
 * relocation can run until we have entered the high 64-bit alias.
 */
.section .text._start,"ax",@progbits
.global _start
.code32
_start:
    cli
    cld
    mov dword ptr [{scratch} + 0x3030], ebx
    mov dword ptr [{scratch} + 0x3034], 0
    mov esp, {scratch} + 0x80000

    mov dx, 0x3f8
    mov al, 'P'
    out dx, al
    mov al, 'V'
    out dx, al
    mov al, 'H'
    out dx, al
    mov al, 10
    out dx, al

    /* PML4, PDPT, PD: map low 1 GiB both identity and at KERNEL_OFFSET. */
    mov edi, {scratch}
    xor eax, eax
    mov ecx, 3 * 4096 / 4
    rep stosd
    mov eax, {scratch} + 0x1000 + 3
    mov dword ptr [{scratch}], eax
    mov dword ptr [{scratch} + {kernel_slot} * 8], eax
    mov eax, {scratch} + 0x2000 + 3
    mov dword ptr [{scratch} + 0x1000], eax
    xor ecx, ecx
    mov eax, 0x83
2:
    mov dword ptr [{scratch} + 0x2000 + ecx * 8], eax
    add eax, 0x200000
    inc ecx
    cmp ecx, 512
    jb 2b

    /* Null, long-mode code, flat data descriptors. */
    mov dword ptr [{scratch} + 0x3000], 0
    mov dword ptr [{scratch} + 0x3004], 0
    mov dword ptr [{scratch} + 0x3008], 0x0000ffff
    mov dword ptr [{scratch} + 0x300c], 0x00af9a00
    mov dword ptr [{scratch} + 0x3010], 0x0000ffff
    mov dword ptr [{scratch} + 0x3014], 0x00cf9200
    mov word ptr [{scratch} + 0x3020], 23
    mov dword ptr [{scratch} + 0x3022], {scratch} + 0x3000

    mov eax, cr4
    and eax, ~((1 << 17) | (1 << 7))  /* PCID and global pages disabled */
    or eax, 1 << 5                   /* PAE */
    mov cr4, eax
    mov eax, {scratch}
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 1 << 8                   /* EFER.LME */
    wrmsr
    mov eax, cr0
    or eax, (1 << 31) | (1 << 16)     /* PG, WP */
    mov cr0, eax
    lgdt [{scratch} + 0x3020]
    mov eax, offset .Lpa_long
    push 0x08
    push eax
    retf

.code64
.Llong:
    mov ax, 0x10
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov rax, offset .Lpa_high
    mov rcx, {kernel_offset}
    add rax, rcx
    jmp rax
.Lhigh:
    mov rsp, {scratch} + 0x80000
    add rsp, rcx
    /* SSE2 is part of Rust's x86-64 ABI; enable before any Rust executes. */
    mov rax, cr0
    and rax, ~((1 << 2) | (1 << 3))   /* EM, TS clear */
    or rax, 1 << 1                   /* MP */
    mov cr0, rax
    mov rax, cr4
    or rax, (1 << 9) | (1 << 10)      /* OSFXSR, OSXMMEXCPT */
    mov cr4, rax
    xor rbp, rbp
    call {rust_entry}
3:
    cli
    hlt
    jmp 3b

.set .Lpa_long, .Llong - _start + {entry}
.set .Lpa_high, .Lhigh - _start + {entry}
