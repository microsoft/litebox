// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: getitimer happy path + cross-syscall observation (alarm sets the
// ITIMER_REAL state that getitimer reads back) and error branches.
// Goes through syscall(SYS_getitimer, ...) to exercise the raw kernel surface
// that LiteBox intercepts rather than the libc wrapper.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg)                                                \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d: %s)\n",        \
                    __func__, __LINE__, msg, errno, strerror(errno));         \
            exit(1);                                                          \
        }                                                                     \
    } while (0)

static int raw_getitimer(int which, struct itimerval *curr_value) {
    return (int)syscall(SYS_getitimer, which, curr_value);
}

static void test_getitimer_no_timer_set(void) {
    // ITIMER_REAL with no timer armed: both substructures must be zero.
    // Cancel any inherited alarm first so the slate is clean.
    alarm(0);
    struct itimerval iv;
    memset(&iv, 0xff, sizeof(iv));
    int rc = raw_getitimer(ITIMER_REAL, &iv);
    TEST_ASSERT(rc == 0, "getitimer(ITIMER_REAL) success");
    TEST_ASSERT(iv.it_value.tv_sec == 0 && iv.it_value.tv_usec == 0,
                "it_value zero when no timer armed");
    TEST_ASSERT(iv.it_interval.tv_sec == 0 && iv.it_interval.tv_usec == 0,
                "it_interval zero when no timer armed");
}

static void test_getitimer_after_alarm(void) {
    // alarm(N) is documented as equivalent to setitimer(ITIMER_REAL, {0, N}, NULL).
    // Setting alarm(10) and immediately reading should show ~10s remaining in
    // it_value and zero interval.
    alarm(0);
    unsigned int prev = alarm(10);
    TEST_ASSERT(prev == 0, "no prior alarm");

    struct itimerval iv;
    memset(&iv, 0xff, sizeof(iv));
    int rc = raw_getitimer(ITIMER_REAL, &iv);
    TEST_ASSERT(rc == 0, "getitimer success after alarm");

    // it_value should be in (0, 10] seconds — a tv_sec of 9 or 10 with any
    // microseconds is acceptable, depending on how much wall-clock time
    // elapsed between alarm() and getitimer().
    long total_us =
        (long)iv.it_value.tv_sec * 1000000L + (long)iv.it_value.tv_usec;
    TEST_ASSERT(total_us > 0 && total_us <= 10 * 1000000L,
                "it_value in (0, 10s] after alarm(10)");
    TEST_ASSERT(iv.it_interval.tv_sec == 0 && iv.it_interval.tv_usec == 0,
                "it_interval zero because alarm() never sets an interval");

    alarm(0);
}

static void test_getitimer_virtual_and_prof_zero(void) {
    // ITIMER_VIRTUAL and ITIMER_PROF are valid `which` values. When no
    // setitimer has armed them (and Linux's per-process default is "not
    // armed"), getitimer reports zeroed itimerval.
    for (int which = ITIMER_VIRTUAL; which <= ITIMER_PROF; which++) {
        struct itimerval iv;
        memset(&iv, 0xff, sizeof(iv));
        int rc = raw_getitimer(which, &iv);
        TEST_ASSERT(rc == 0, "getitimer ITIMER_VIRTUAL/PROF success");
        TEST_ASSERT(iv.it_value.tv_sec == 0 && iv.it_value.tv_usec == 0,
                    "it_value zero for unarmed ITIMER_VIRTUAL/PROF");
        TEST_ASSERT(iv.it_interval.tv_sec == 0 && iv.it_interval.tv_usec == 0,
                    "it_interval zero for unarmed ITIMER_VIRTUAL/PROF");
    }
}

static void test_getitimer_einval(void) {
    // `which` outside {0, 1, 2} → EINVAL.
    struct itimerval iv;
    errno = 0;
    int rc = raw_getitimer(99, &iv);
    TEST_ASSERT(rc == -1 && errno == EINVAL,
                "getitimer with bogus which → EINVAL");
}

static void test_getitimer_efault(void) {
    // NULL curr_value pointer → EFAULT.
    errno = 0;
    int rc = raw_getitimer(ITIMER_REAL, NULL);
    TEST_ASSERT(rc == -1 && errno == EFAULT,
                "getitimer with NULL curr_value → EFAULT");
}

int main(void) {
    printf("getitimer tests starting...\n");
    test_getitimer_no_timer_set();
    test_getitimer_after_alarm();
    test_getitimer_virtual_and_prof_zero();
    test_getitimer_einval();
    test_getitimer_efault();
    printf("All getitimer tests passed.\n");
    return 0;
}
