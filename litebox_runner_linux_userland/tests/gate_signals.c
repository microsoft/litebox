// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <signal.h>
#include <stdint.h>

static volatile sig_atomic_t alarm_count;

static void alarm_handler(int signo) {
    (void)signo;
    alarm_count++;
}

static void install_alarm_handler(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction(SIGALRM) failed");
}

#ifdef __aarch64__

#define GUEST_X16 0x1616161616161616UL
#define GUEST_X17 0x1717171717171717UL

static unsigned long read_guest_tp(void) {
    unsigned long value;
    asm volatile("mrs %0, tpidr_el0" : "=r"(value));
    return value;
}

static int exercise_mrs_gate(void) {
    unsigned long expected = read_guest_tp();
    unsigned long observed = 0;
    sig_atomic_t start = alarm_count;

    alarm(1);
    while (alarm_count == start) {
        asm volatile("mrs %0, tpidr_el0" : "=r"(observed));
        if (observed != expected)
            return 0;
    }
    return 1;
}

static int exercise_msr_gate(void) {
    unsigned long expected = read_guest_tp();
    sig_atomic_t start = alarm_count;

    alarm(1);
    while (alarm_count == start) {
        // Writing back the current virtual guest TP is semantically inert but
        // still forces every iteration through an MSR gate.
        asm volatile("msr tpidr_el0, %0" : : "r"(expected) : "memory");
        if (read_guest_tp() != expected)
            return 0;
    }
    return 1;
}

static int exercise_svc_gate(void) {
    sig_atomic_t start = alarm_count;

    alarm(1);
    while (alarm_count == start) {
        register unsigned long x8 asm("x8") = SYS_getpid;
        register unsigned long x16 asm("x16") = GUEST_X16;
        register unsigned long x17 asm("x17") = GUEST_X17;
        register long result asm("x0");
        asm volatile("svc #0"
                     : "=r"(result), "+r"(x8), "+r"(x16), "+r"(x17)
                     :
                     : "memory", "cc");
        if (result <= 0 || x16 != GUEST_X16 || x17 != GUEST_X17)
            return 0;
    }
    return 1;
}

#else

static int exercise_mrs_gate(void) { return 1; }
static int exercise_msr_gate(void) { return 1; }
static int exercise_svc_gate(void) { return 1; }

#endif

int main(void) {
    install_alarm_handler();
    TEST_ASSERT(exercise_mrs_gate(), "MRS semantics changed while signals were active");
    TEST_ASSERT(exercise_msr_gate(), "MSR semantics changed while signals were active");
    TEST_ASSERT(exercise_svc_gate(), "SVC registers changed while signals were active");
    TEST_ASSERT(alarm_count == 3, "one signal was not delivered in each gate loop");
    TEST_ASSERT(write(1, "gate signals ok\n", 16) == 16, "write after gate loops failed");
    return 0;
}
