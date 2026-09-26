/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Copies /greeting.txt to stdout with open(2), read(2), write(2) and close(2).
// Returns 0 from main on success and 1 if any call reports an error.

    .text
    .globl _main
    .p2align 4
_main:
    pushq %rbx
    subq $256, %rsp
    movl $0x2000005, %eax  // SYS_open
    leaq path(%rip), %rdi
    xorl %esi, %esi         // O_RDONLY
    xorl %edx, %edx
    syscall
    jc fail
    movl %eax, %ebx
    movl $0x2000003, %eax  // SYS_read
    movl %ebx, %edi
    movq %rsp, %rsi
    movl $256, %edx
    syscall
    jc fail
    movl %eax, %edx
    movl $0x2000004, %eax  // SYS_write
    movl $1, %edi
    movq %rsp, %rsi
    syscall
    jc fail
    movl $0x2000006, %eax  // SYS_close
    movl %ebx, %edi
    syscall
    jc fail
    xorl %eax, %eax
    jmp done
fail:
    movl $1, %eax
done:
    addq $256, %rsp
    popq %rbx
    ret

    .section __TEXT,__cstring
path:
    .asciz "/greeting.txt"
