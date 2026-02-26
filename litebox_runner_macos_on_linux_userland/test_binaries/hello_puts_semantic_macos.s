.globl _start
.globl _main
.globl _puts

.section __DATA,__data
stored_ptr:
    .quad 0
message:
    .asciz "Hello world"
newline:
    .byte 0x0a

.section __TEXT,__text
_puts:
    movq %rdi, stored_ptr(%rip)
    xorl %eax, %eax
    ret

_main:
    leaq message(%rip), %rdi
    call _puts
    xorl %eax, %eax
    ret

_start:
    call _main

    movq stored_ptr(%rip), %rsi
    xorq %rdx, %rdx
1:
    cmpb $0, (%rsi,%rdx)
    je 2f
    incq %rdx
    jmp 1b
2:
    movq $0x2000004, %rax
    movq $1, %rdi
    syscall

    movq $0x2000004, %rax
    movq $1, %rdi
    leaq newline(%rip), %rsi
    movq $1, %rdx
    syscall

    movq $0x2000001, %rax
    xorq %rdi, %rdi
    syscall
