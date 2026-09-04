// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __aarch64__

static volatile sig_atomic_t handler_ran;

static void handler(int signo) {
    (void)signo;
    asm volatile("movi v0.16b, #0xaa\n\tmovi v8.16b, #0xbb" : : : "v0", "v8");
    handler_ran = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction failed");

    uint64_t expected0[2] = {UINT64_C(0x8877665544332211), UINT64_C(0x0123456789abcdef)};
    uint64_t expected8[2] = {UINT64_C(0x1020304050607080), UINT64_C(0xfedcba9876543210)};
    uint64_t observed0[2];
    uint64_t observed8[2];

    long pid = getpid();
    long tid = syscall(SYS_gettid);
    register long x0 asm("x0") = pid;
    register long x1 asm("x1") = tid;
    register long x2 asm("x2") = SIGUSR1;
    register long x8 asm("x8") = SYS_tgkill;
    asm volatile("ldr q0, [%[expected0]]\n\t"
                 "ldr q8, [%[expected8]]\n\t"
                 "svc #0\n\t"
                 "str q0, [%[observed0]]\n\t"
                 "str q8, [%[observed8]]"
                 : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x8)
                 : [expected0] "r"(expected0), [expected8] "r"(expected8),
                   [observed0] "r"(observed0), [observed8] "r"(observed8)
                 : "v0", "v8", "memory", "cc");
    TEST_ASSERT(x0 == 0, "tgkill failed");

    TEST_ASSERT(handler_ran, "handler did not run");
    TEST_ASSERT(memcmp(observed0, expected0, sizeof(expected0)) == 0,
                "v0 was not restored after signal delivery");
    TEST_ASSERT(memcmp(observed8, expected8, sizeof(expected8)) == 0,
                "v8 was not restored after signal delivery");
    return 0;
}

#else

int main(void) {
    return 0;
}

#endif
