.globl _main

.section __TEXT,__text
_main:
    leaq message(%rip), %rsi
    movq $14, %rdx
    movq $1, %rdi
    movq $0x2000004, %rax
    syscall

    xorq %rdi, %rdi
    movq $0x2000001, %rax
    syscall

.section __TEXT,__cstring
message:
    .asciz "Hello, World!\n"
