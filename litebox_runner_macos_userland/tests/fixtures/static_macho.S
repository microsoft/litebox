/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

// One static Mach-O E2E fixture. Gate ABI, startup stack, and process checks
// always run; the Rust test sets TEST_STDIO for the optional I/O checks.
.ifndef TEST_STDIO
.set TEST_STDIO, 0
.endif
.global _start
.p2align 2
_start:
    // argc, argv terminator, envp, and empty apple vector.
    ldr x9, [sp]
    cmp x9, #3
    b.ne fail
    ldr x9, [sp, #32]
    cbnz x9, fail
    ldr x9, [sp, #40]
    ldrb w10, [x9]
    cmp w10, #'K'
    b.ne fail
    ldr x9, [sp, #48]
    cbnz x9, fail
    ldr x9, [sp, #56]
    cbnz x9, fail

    mov x19, sp
    mov x9, #0x1234
    stp x9, x9, [sp, #-16]
    stp x9, x9, [sp, #-32]
    stp x9, x9, [sp, #-48]
    stp x9, x9, [sp, #-64]
    stp x9, x9, [sp, #-80]
    stp x9, x9, [sp, #-96]
    stp x9, x9, [sp, #-112]
    stp x9, x9, [sp, #-128]
    movi v0.16b, #0x11
    movi v8.16b, #0x22
    movi v31.16b, #0x44
    mov x20, #1000
again:
    mov x0, #77
    mov x1, #88
    mov x8, #93 // Linux exit; must not select the Darwin syscall.
    mov x16, #20 // Darwin getpid
    mov x17, #0x5678
    mov x30, #0x6789
    mov x9, #0xb0000000
    msr nzcv, x9
    svc #0x80
    b.cs fail
    mrs x10, nzcv
    mov x9, #0x90000000
    cmp x10, x9
    b.ne fail
    cmp x0, #1 // Virtual PID, not the host process's PID.
    b.ne fail
    cmp x1, #88
    b.ne fail
    cmp x16, #20
    b.ne fail
    mov x9, #0x5678
    cmp x17, x9
    b.ne fail
    mov x9, #0x6789
    cmp x30, x9
    b.ne fail
    mov x10, sp
    cmp x10, x19
    b.ne fail
    subs x20, x20, #1
    b.ne again

    // Every red-zone word must survive all 1000 syscall round trips.
    sub x10, sp, #128
    mov x13, #8
    mov x9, #0x1234
redzone:
    ldp x11, x12, [x10], #16
    cmp x11, x9
    b.ne fail
    cmp x12, x9
    b.ne fail
    subs x13, x13, #1
    b.ne redzone

    umov x10, v0.d[0]
    mov x9, #0x1111111111111111
    cmp x10, x9
    b.ne fail
    umov x10, v8.d[1]
    mov x9, #0x2222222222222222
    cmp x10, x9
    b.ne fail
    umov x10, v31.d[1]
    mov x9, #0x4444444444444444
    cmp x10, x9
    b.ne fail

    // The MRS gate reads the guest's virtual thread pointer.
    mrs x4, tpidrro_el0
    cbnz x4, fail

    mov x16, #999
    svc #0x80
    b.cc fail
    cmp x0, #78 // positive Darwin ENOSYS
    b.ne fail
    mov x16, #39 // getppid
    svc #0x80
    cbnz x0, fail
    mov x16, #24 // getuid
    svc #0x80
    cmp x0, #1000
    b.ne fail
    mov x16, #25 // geteuid
    svc #0x80
    cmp x0, #1000
    b.ne fail
    mov x16, #47 // getgid
    svc #0x80
    cmp x0, #1000
    b.ne fail
    mov x16, #43 // getegid
    svc #0x80
    cmp x0, #1000
    b.ne fail

    // Native Darwin stubs write the signed trap selector through w16. Mach
    // returns preserve condition flags rather than applying BSD carry handling.
    mov w16, #-3 // mach_absolute_time
    mov x9, #0x20000000
    msr nzcv, x9
    svc #0x80
    b.cc fail
    cbz x0, fail
    mov x21, x0
    mov w16, #-3
    mov x9, #0x20000000
    msr nzcv, x9
    svc #0x80
    b.cc fail
    cmp x0, x21
    b.lo fail

    // Waiting for an already-reached absolute deadline succeeds immediately.
    mov w16, #-90 // mach_wait_until
    mov x9, #0x20000000
    msr nzcv, x9
    svc #0x80
    b.cc fail
    cbnz x0, fail

    sub x0, sp, #16
    stp xzr, xzr, [x0]
    mov w16, #-89 // mach_timebase_info
    mov x9, #0x20000000
    msr nzcv, x9
    svc #0x80
    b.cc fail
    cbnz x0, fail
    ldp w9, w10, [sp, #-16]
    cbz w9, fail
    cbz w10, fail

    // XNU ignores mach_timebase_info's copyout failure.
    mov x0, #0
    mov w16, #-89
    mov x9, #0x20000000
    msr nzcv, x9
    svc #0x80
    b.cc fail
    cbnz x0, fail

    // Negative descriptors return EBADF.
    mov x0, #-1
    mov x16, #6
    svc #0x80
    b.cc fail
    cmp x0, #9
    b.ne fail

.if TEST_STDIO
    // Bad user pointers return EFAULT without crashing the runner.
    mov x0, #1
    mov x1, #0
    mov x2, #1
    mov x16, #4
    svc #0x80
    b.cc fail
    cmp x0, #14
    b.ne fail

    // A zero-length write must not dereference NULL.
    mov x0, #1
    mov x2, #0
    mov x16, #397
    svc #0x80
    b.cs fail
    cbnz x0, fail

    // Read into guest memory, then echo to stdout. BSD descriptors use the
    // low 32 bits of their argument register.
    adrp x19, buffer@PAGE
    add x19, x19, buffer@PAGEOFF
    mov x0, #0
    mov x1, x19
    mov x2, #6
    mov x16, #396
    svc #0x80
    b.cs fail
    cmp x0, #6
    b.ne fail
    mov x2, x0
    mov x0, #1
    movk x0, #0xabcd, lsl #32
    mov x1, x19
    mov x16, #397
    svc #0x80
    b.cs fail
    cmp x0, #6
    b.ne fail

    // Dup uses LiteBox's shared entry and a new raw descriptor slot.
    mov x0, #1
    mov x16, #41
    svc #0x80
    b.cs fail
    cmp x0, #3
    b.ne fail

    // Closing the original does not close the duplicate or host stdout.
    mov x0, #1
    mov x16, #399
    svc #0x80
    b.cs fail
    cbnz x0, fail
    mov x0, #1
    mov x16, #4
    svc #0x80
    b.cc fail
    cmp x0, #9
    b.ne fail
    mov x0, #3
    mov x2, #0
    mov x16, #4
    svc #0x80
    b.cs fail
    cbnz x0, fail

    mov x0, #2
    mov x1, x19
    mov x2, #6
    mov x16, #4
    svc #0x80
    b.cs fail
.else
    // Normal runner builds must not expose local stdio, even for empty I/O.
    mov x0, #1
    mov x1, #0
    mov x2, #0
    mov x16, #4
    svc #0x80
    b.cc fail
    cmp x0, #9
    b.ne fail
.endif

    // The guest exit status is truncated to the low eight bits.
    mov x0, #298
    b exit
fail:
    mov x0, #99
exit:
    mov x16, #1
    svc #0x80
    brk #0

.if TEST_STDIO
.bss
.p2align 4
buffer:
    .space 16
.endif
