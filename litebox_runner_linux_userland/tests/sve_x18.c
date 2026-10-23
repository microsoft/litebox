// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Plain MOVs initialize guest x18 before SVE address/scalar reads and writes.
// With x18 virtualization it lives in TLS, so ungated SVE uses see physical x18.

#include "helpers.h"

#include <stdint.h>

#if defined(__aarch64__)

// Largest architectural vector length in 64-bit elements.
#define MAX_VL_DWORDS 32

static uint64_t src[4 * MAX_VL_DWORDS];
static uint64_t dst[5 * MAX_VL_DWORDS];

struct scalars {
    uint64_t cntd;
    uint64_t incd;
    uint64_t addvl;
    uint64_t lastb;
    uint64_t whilelo_active;
};

int main(void) {
    uint64_t vl;
    asm volatile(".arch_extension sve\n\trdvl %0, #1" : "=r"(vl));
    const uint64_t n = vl / 8;
    TEST_ASSERT(vl % 16 == 0 && n <= MAX_VL_DWORDS, "unexpected vector length");
    for (size_t i = 0; i < sizeof(src) / sizeof(src[0]); i++) {
        src[i] = 0x5e00 + i * 3;
    }

    struct scalars out;
    asm volatile(".arch_extension sve\n\t"
                 "ptrue p0.d\n\t"
                 "mov x18, %[src]\n\t"
                 "ld1d {z0.d}, p0/z, [x18]\n\t"
                 "ld1d {z1.d}, p0/z, [x18, #1, mul vl]\n\t"
                 "mov x18, #3\n\t"
                 "ld1d {z2.d}, p0/z, [%[src], x18, lsl #3]\n\t"
                 "mov x18, %[dst]\n\t"
                 "st1d {z0.d}, p0, [x18]\n\t"
                 "st1d {z1.d}, p0, [x18, #1, mul vl]\n\t"
                 "st1d {z2.d}, p0, [x18, #2, mul vl]\n\t"
                 "mov x18, #5\n\t"
                 "dup z3.d, x18\n\t"
                 "index z4.d, x18, #2\n\t"
                 "st1d {z3.d}, p0, [%[dst], #3, mul vl]\n\t"
                 "st1d {z4.d}, p0, [%[dst], #4, mul vl]\n\t"
                 "cntd x18\n\t"
                 "str x18, [%[out], #0]\n\t"
                 "incd x18, all, mul #2\n\t"
                 "str x18, [%[out], #8]\n\t"
                 "addvl x18, x18, #1\n\t"
                 "str x18, [%[out], #16]\n\t"
                 "lastb x18, p0, z0.d\n\t"
                 "str x18, [%[out], #24]\n\t"
                 "mov x18, #1\n\t"
                 "whilelo p1.d, xzr, x18\n\t"
                 "cntp x9, p0, p1.d\n\t"
                 "str x9, [%[out], #32]\n\t"
                 :
                 : [src] "r"(src), [dst] "r"(dst), [out] "r"(&out)
                 : "x9", "x18", "memory", "cc", "v0", "v1", "v2", "v3", "v4", "p0", "p1");

    for (uint64_t i = 0; i < n; i++) {
        TEST_ASSERT(dst[i] == src[i], "ld1d/st1d with x18 base");
        TEST_ASSERT(dst[n + i] == src[n + i], "ld1d/st1d with x18 base and VL offset");
        TEST_ASSERT(dst[2 * n + i] == src[3 + i], "ld1d with x18 index");
        TEST_ASSERT(dst[3 * n + i] == 5, "dup from x18");
        TEST_ASSERT(dst[4 * n + i] == 5 + 2 * i, "index from x18");
    }
    TEST_ASSERT(out.cntd == n, "cntd into x18");
    TEST_ASSERT(out.incd == 3 * n, "incd of x18");
    TEST_ASSERT(out.addvl == 3 * n + vl, "addvl of x18");
    TEST_ASSERT(out.lastb == src[n - 1], "lastb into x18");
    TEST_ASSERT(out.whilelo_active == 1, "whilelo bounded by x18");

    printf("sve x18 ok\n");
    return 0;
}

#else

int main(void) {
    return 0;
}

#endif
