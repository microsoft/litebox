// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: getitimer happy path + cross-syscall observation (alarm sets the
// ITIMER_REAL state that getitimer reads back) and error branches.
// Goes through syscall(SYS_getitimer, ...) to exercise the raw kernel surface
// that LiteBox intercepts rather than the libc wrapper.

#include "helpers.h"

static int raw_getitimer(int which, struct itimerval *curr_value) {
    return (int)syscall(SYS_getitimer, which, curr_value);
}

static void expect_unarmed_timer(int which, const char *op) {
    struct itimerval iv;

    memset(&iv, 0xff, sizeof(iv));
    TEST_ASSERT(raw_getitimer(which, &iv) == 0, op);
    TEST_ASSERT(iv.it_value.tv_sec == 0 && iv.it_value.tv_usec == 0,
                "it_value zero when timer is unarmed");
    TEST_ASSERT(iv.it_interval.tv_sec == 0 && iv.it_interval.tv_usec == 0,
                "it_interval zero when timer is unarmed");
}

static void test_getitimer_no_timer_set(void) {
    alarm(0);
    expect_unarmed_timer(ITIMER_REAL, "getitimer(ITIMER_REAL) unarmed");
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

    long total_us = itimer_value_us(&iv);
    TEST_ASSERT(total_us > 0 && total_us <= 10 * 1000000L,
                "it_value in (0, 10s] after alarm(10)");
    TEST_ASSERT(iv.it_interval.tv_sec == 0 && iv.it_interval.tv_usec == 0,
                "it_interval zero because alarm() never sets an interval");

    alarm(0);
}

static void test_getitimer_virtual_and_prof_zero(void) {
    for (int which = ITIMER_VIRTUAL; which <= ITIMER_PROF; which++) {
        expect_unarmed_timer(which, "getitimer ITIMER_VIRTUAL/PROF unarmed");
    }
}

static void test_getitimer_einval(void) {
    struct itimerval iv;
    errno = 0;
    int rc = raw_getitimer(99, &iv);
    TEST_ASSERT(rc == -1 && errno == EINVAL,
                "getitimer with bogus which -> EINVAL");
}

static void test_getitimer_efault(void) {
    errno = 0;
    int rc = raw_getitimer(ITIMER_REAL, NULL);
    TEST_ASSERT(rc == -1 && errno == EFAULT,
                "getitimer with NULL curr_value -> EFAULT");
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
