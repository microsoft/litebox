// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The guest-visible SVE syscall ABI, as on Linux for a CPU whose only vector
// length is the current one:
// - AT_HWCAP/AT_HWCAP2 equal the allowlisted host values and hide other features;
// - without SVE, PR_SVE_SET_VL/PR_SVE_GET_VL fail with EINVAL;
// - with SVE, P0-P15 and FFR read zero after a syscall, and the PR_SVE_* prctls
//   report and validate the VL. LiteBox accepts PR_SVE_VL_INHERIT but does not
//   report it, since the VL is fixed.
// argv[1]/argv[2] are the expected AT_HWCAP/AT_HWCAP2.

#include "helpers.h"

#include <stdint.h>
#include <sys/auxv.h>
#include <sys/prctl.h>

#if defined(__aarch64__)

// Largest architectural vector length in bytes.
#define MAX_VL 256

static void check_predicates_after_syscall(unsigned long vl) {
    static uint8_t p[16 * MAX_VL / 8];
    static uint8_t ffr[MAX_VL / 8];
    memset(p, 0xff, sizeof(p));
    memset(ffr, 0xff, sizeof(ffr));
    register long x8 asm("x8") = SYS_getpid;
    register long x0 asm("x0");
#define PS(n) "str p" #n ", [%[p], #" #n ", mul vl]\n\t"
    asm volatile(".arch_extension sve\n\t"
                 "ptrue p0.b\n\t"
                 "ptrue p5.h\n\t"
                 "ptrue p15.s\n\t"
                 "setffr\n\t"
                 "svc #0\n\t"
                 PS(0) PS(1) PS(2) PS(3) PS(4) PS(5) PS(6) PS(7)
                 PS(8) PS(9) PS(10) PS(11) PS(12) PS(13) PS(14) PS(15)
                 "rdffr p0.b\n\t"
                 "str p0, [%[ffr]]\n\t"
                 : "=&r"(x0)
                 : "r"(x8), [p] "r"(p), [ffr] "r"(ffr)
                 : "memory", "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9",
                   "p10", "p11", "p12", "p13", "p14", "p15", "ffr");
#undef PS
    TEST_ASSERT(x0 == getpid(), "raw getpid returned the wrong value");
    for (size_t i = 0; i < 16 * vl / 8; i++) {
        TEST_ASSERT(p[i] == 0, "a P register is nonzero after a syscall");
    }
    for (size_t i = 0; i < vl / 8; i++) {
        TEST_ASSERT(ffr[i] == 0, "FFR is nonzero after a syscall");
    }
}

static void check_hwcaps(unsigned long expected_hwcap, unsigned long expected_hwcap2) {
    unsigned long hwcap = getauxval(AT_HWCAP);
    unsigned long hwcap2 = getauxval(AT_HWCAP2);
    TEST_ASSERT(hwcap == expected_hwcap, "AT_HWCAP differs from the allowlisted host bits");
    TEST_ASSERT(hwcap2 == expected_hwcap2, "AT_HWCAP2 differs from the allowlisted host bits");
    TEST_ASSERT((hwcap & (HWCAP_ATOMICS | HWCAP_CPUID)) == 0, "AT_HWCAP shows hidden features");
    TEST_ASSERT((hwcap2 & HWCAP2_SME) == 0, "AT_HWCAP2 shows SME");
}

static long get_vl(void) {
    return prctl(PR_SVE_GET_VL, 0, 0, 0, 0);
}

static long set_vl(unsigned long arg) {
    return prctl(PR_SVE_SET_VL, arg, 0, 0, 0);
}

static void expect_einval(long ret, const char *msg) {
    TEST_ASSERT(ret == -1 && errno == EINVAL, msg);
}

static void check_prctl(unsigned long vl) {
    TEST_ASSERT(get_vl() == (long)vl, "PR_SVE_GET_VL differs from rdvl");
    TEST_ASSERT(set_vl(8192) == (long)vl, "PR_SVE_SET_VL did not select the only VL");
    TEST_ASSERT(set_vl(16) == (long)vl, "PR_SVE_SET_VL did not select the only VL");
    TEST_ASSERT(set_vl(vl | PR_SVE_SET_VL_ONEXEC) == (long)vl, "PR_SVE_SET_VL_ONEXEC");
    TEST_ASSERT(set_vl(vl | PR_SVE_VL_INHERIT | PR_SVE_SET_VL_ONEXEC) == (long)vl,
                "PR_SVE_SET_VL rejected PR_SVE_VL_INHERIT");
    TEST_ASSERT(get_vl() == (long)vl, "PR_SVE_GET_VL differs from PR_SVE_SET_VL");
    expect_einval(set_vl(0), "PR_SVE_SET_VL accepted VL 0");
    expect_einval(set_vl(vl + 1), "PR_SVE_SET_VL accepted an unaligned VL");
    expect_einval(set_vl(8192 + 16), "PR_SVE_SET_VL accepted a VL above SVE_VL_MAX");
    expect_einval(set_vl(vl | (1UL << 16)), "PR_SVE_SET_VL accepted an unknown flag");
    expect_einval(set_vl(vl | (1UL << 19)), "PR_SVE_SET_VL accepted an unknown flag");
    expect_einval(prctl(PR_SME_GET_VL, 0, 0, 0, 0), "PR_SME_GET_VL succeeded without SME");
}

int main(int argc, char **argv) {
    TEST_ASSERT(argc == 3, "usage: sve_syscall_abi HWCAP HWCAP2");
    unsigned long hwcap = strtoul(argv[1], NULL, 0);
    check_hwcaps(hwcap, strtoul(argv[2], NULL, 0));
    if ((hwcap & HWCAP_SVE) == 0) {
        expect_einval(get_vl(), "PR_SVE_GET_VL succeeded without SVE");
        expect_einval(set_vl(16), "PR_SVE_SET_VL succeeded without SVE");
        printf("sve syscall abi ok\n");
        return 0;
    }

    unsigned long vl;
    asm volatile(".arch_extension sve\n\trdvl %0, #1" : "=r"(vl));
    TEST_ASSERT(vl % 16 == 0 && vl <= MAX_VL, "unexpected vector length");
    check_predicates_after_syscall(vl);
    check_prctl(vl);
    printf("sve syscall abi ok\n");
    return 0;
}

#else

int main(void) {
    return 0;
}

#endif
