/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Maps an anonymous read-write page with mmap(2), copies a message into it,
// writes the page's copy to stdout and unmaps it with munmap(2). Returns 0 from
// main on success and 1 if any call reports an error.

    .text
    .globl _main
    .p2align 4
_main:
    pushq %rbx
    movl $0x20000c5, %eax  // SYS_mmap (197)
    xorl %edi, %edi
    movl $4096, %esi
    movl $3, %edx          // PROT_READ | PROT_WRITE
    movl $0x1002, %r10d    // MAP_ANON | MAP_PRIVATE
    movq $-1, %r8
    xorl %r9d, %r9d
    syscall
    jc fail
    movq %rax, %rbx
    movq %rbx, %rdi
    leaq message(%rip), %rsi
    movl $(message_end - message), %ecx
    rep movsb
    movl $0x2000004, %eax  // SYS_write
    movl $1, %edi
    movq %rbx, %rsi
    movl $(message_end - message), %edx
    syscall
    jc fail
    movl $0x2000049, %eax  // SYS_munmap (73)
    movq %rbx, %rdi
    movl $4096, %esi
    syscall
    jc fail
    xorl %eax, %eax
    popq %rbx
    ret
fail:
    movl $1, %eax
    popq %rbx
    ret

    .section __TEXT,__const
message:
    .ascii "written through an mmap page\n"
message_end:
