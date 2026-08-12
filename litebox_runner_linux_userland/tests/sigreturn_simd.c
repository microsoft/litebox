// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <signal.h>
#include <stdint.h>

#ifdef __aarch64__

static volatile sig_atomic_t handler_ran;

static void handler(int signo) {
    (void)signo;
    handler_ran = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction failed");

    uint64_t expected = UINT64_C(0x8877665544332211);
    uint64_t observed;

    asm volatile("fmov d8, %0" : : "r"(expected) : "d8");
    TEST_ASSERT(raise(SIGUSR1) == 0, "raise failed");
    asm volatile("fmov %0, d8" : "=r"(observed));

    TEST_ASSERT(handler_ran, "handler did not run");
    TEST_ASSERT(observed == expected, "d8 was not restored after signal delivery");
    return 0;
}

#else

int main(void) {
    return 0;
}

#endif
