/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Prints argv[1..argc] one per line, reading argc and argv from the
// main(argc, argv, envp, apple) registers.

    .text
    .globl _main
    .p2align 4
_main:
    pushq %rbx
    pushq %r12
    pushq %r13
    movl %edi, %r12d        // argc
    movq %rsi, %r13         // argv
    movl $1, %ebx
next:
    cmpl %r12d, %ebx
    jge out
    movq (%r13,%rbx,8), %rsi
    xorl %edx, %edx
length:
    cmpb $0, (%rsi,%rdx)
    je print
    incq %rdx
    jmp length
print:
    movl $0x2000004, %eax  // SYS_write
    movl $1, %edi
    syscall
    movl $0x2000004, %eax  // SYS_write
    movl $1, %edi
    leaq newline(%rip), %rsi
    movl $1, %edx
    syscall
    incl %ebx
    jmp next
out:
    xorl %eax, %eax
    popq %r13
    popq %r12
    popq %rbx
    ret

    .section __TEXT,__const
newline:
    .ascii "\n"
