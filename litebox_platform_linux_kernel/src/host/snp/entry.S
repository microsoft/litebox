.global sandbox_process_ret_from_fork;

    .code64
    .text

.section .head.text,"ax"
sandbox_process_ret_from_fork:
    mov rsi, r15
    jmp thread_start
1:  /* hlt the machine */
    hlt
    jmp	1b
