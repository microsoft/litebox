// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Linux AArch64 SVC preserves x16/x17; unlike a function-call veneer, the
// syscall ABI permits the compiler to keep both registers live across SVC.

#include "helpers.h"

#ifdef __aarch64__

#define SENTINEL_X16 12345L
#define SENTINEL_X17 54321L

static long probe_x16(void) {
    register long x8 asm("x8") = __NR_write;
    register long x0 asm("x0") = 1;
    register long x1 asm("x1") = (long)"";
    register long x2 asm("x2") = 0;
    register long x16 asm("x16") = SENTINEL_X16;

    asm volatile("svc #0"
                 : "+r"(x0), "+r"(x16)
                 : "r"(x8), "r"(x1), "r"(x2)
                 : "memory");

    TEST_ASSERT(x0 == 0, "write(1, \"\", 0) should return 0");
    return x16;
}

static long probe_x17(void) {
    register long x8 asm("x8") = __NR_write;
    register long x0 asm("x0") = 1;
    register long x1 asm("x1") = (long)"";
    register long x2 asm("x2") = 0;
    register long x17 asm("x17") = SENTINEL_X17;

    asm volatile("svc #0"
                 : "+r"(x0), "+r"(x17)
                 : "r"(x8), "r"(x1), "r"(x2)
                 : "memory");

    TEST_ASSERT(x0 == 0, "write(1, \"\", 0) should return 0");
    return x17;
}

int main(void) {
    long x16 = probe_x16();
    if (x16 != SENTINEL_X16) {
        fprintf(stderr, "FAIL: x16 not preserved across svc: got %ld, want %ld\n", x16,
                SENTINEL_X16);
        return 1;
    }

    long x17 = probe_x17();
    if (x17 != SENTINEL_X17) {
        fprintf(stderr, "FAIL: x17 not preserved across svc: got %ld, want %ld\n", x17,
                SENTINEL_X17);
        return 1;
    }

    return 0;
}

#else // !__aarch64__

int main(void) {
    return 0;
}

#endif // __aarch64__
