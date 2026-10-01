/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

.text
.p2align 2
.global island_getpid
.type island_getpid, %function
island_getpid:
    mov x8, #172
#ifdef MANY_SITES
    // Exceed the 64KiB LOAD gap so dlopen must place external AOT islands.
    .rept 8192
    svc #0
    .endr
#else
    svc #0
#endif
    ret
.size island_getpid, .-island_getpid
#ifdef LARGE
.space 0x4800
#endif
.data
.quad 123
.section .note.GNU-stack,"",%progbits
