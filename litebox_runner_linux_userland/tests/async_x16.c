// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// x16 must survive asynchronous entry to a signal handler and rt_sigreturn;
// neither resume has a rewritten syscall site's outbound stub.

#include "helpers.h"

#include <signal.h>

static volatile sig_atomic_t alarm_count = 0;

static void alarm_handler(int signo) {
    (void)signo;
    alarm_count++;
}

static void install_alarm_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction(SIGALRM) failed");
}

#ifdef __aarch64__

#define SENTINEL_X16 0x1234123412341234L

// One asm block prevents the compiler from spilling or reloading x16.
static long spin_with_sentinel_in_x16(volatile sig_atomic_t *flag) {
    register long x16 asm("x16") = SENTINEL_X16;
    long observed;

    asm volatile("1:\n\t"
                 "ldr w0, [%[flag]]\n\t"
                 "cbz w0, 1b\n\t"
                 "mov %[out], x16"
                 : [out] "=r"(observed), "+r"(x16)
                 : [flag] "r"(flag)
                 : "x0", "memory");

    return observed;
}

#else // !__aarch64__

static long spin_with_sentinel_in_x16(volatile sig_atomic_t *flag) {
    while (*flag == 0) {
    }
    return 0;
}

#endif // __aarch64__

int main(void) {
    install_alarm_handler();

    alarm_count = 0;
    alarm(1);

    long observed = spin_with_sentinel_in_x16(&alarm_count);

    TEST_ASSERT(alarm_count == 1, "SIGALRM was not delivered during the userspace spin");

#ifdef __aarch64__
    if (observed != SENTINEL_X16) {
        fprintf(stderr, "FAIL: x16 not preserved across an asynchronous resume: got 0x%lx, want 0x%lx\n",
                observed, SENTINEL_X16);
        return 1;
    }
#else
    (void)observed;
#endif

    TEST_ASSERT(write(1, "async x16 ok\n", 13) == 13, "write after the spin failed");
    return 0;
}
