/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

.global sandbox_process_ret_from_fork;

    .code64
    .text

.section .head.text,"ax"
sandbox_process_ret_from_fork:
    and     rsp, -16                   /* align stack to 16 bytes */
    call    thread_start
1:  /* hlt the machine */
    hlt
    jmp	1b
