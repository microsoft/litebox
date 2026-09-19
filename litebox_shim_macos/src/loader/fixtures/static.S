/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// Link with ld -static -e _start; no libc or runtime relocations are required.
.global _start
.p2align 2
_start:
    // argc and the argv/envp/apple terminators.
    ldr x9, [sp]
    cmp x9, #1
    b.ne fail
    ldr x9, [sp, #16]
    cbnz x9, fail
    ldr x9, [sp, #32]
    cbnz x9, fail
    ldr x9, [sp, #48]
    cbnz x9, fail

    // Initialized data must survive loading and be writable.
    adrp x9, initialized@PAGE
    add x9, x9, initialized@PAGEOFF
    ldr x10, [x9]
    cmp x10, #1234
    b.ne fail
    str xzr, [x9]

    // Every BSS word must be zero, including pages past the file data.
    adrp x9, buffer@PAGE
    add x9, x9, buffer@PAGEOFF
    mov x10, #4096
check_bss:
    ldr x11, [x9], #8
    cbnz x11, fail
    subs x10, x10, #1
    b.ne check_bss
    mov x0, #42
    b exit
fail:
    mov x0, #99
exit:
    mov x16, #1
    svc #0x80
    brk #0

.data
.p2align 3
initialized:
    .quad 1234
.bss
.p2align 4
buffer:
    .space 32768
