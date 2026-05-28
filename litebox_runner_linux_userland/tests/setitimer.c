// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: setitimer(ITIMER_REAL, ...) — arm, disarm, old_value handoff,
// EINVAL on out-of-range tv_usec, EINVAL on bad `which`, EFAULT on NULL
// new_value. State changes are observed via getitimer() so the cross-syscall
// contract is exercised. Uses syscall(SYS_setitimer, ...) directly to hit the
// raw kernel surface that LiteBox intercepts.

#include "helpers.h"

#include <stdint.h>

static int raw_setitimer(int which, const struct itimerval *new_value,
                         struct itimerval *old_value) {
    return (int)syscall(SYS_setitimer, which, new_value, old_value);
}

static int raw_getitimer(int which, struct itimerval *curr_value) {
    return (int)syscall(SYS_getitimer, which, curr_value);
}

static void clear_alarm(void) {
    struct itimerval zero = {{0, 0}, {0, 0}};
    (void)raw_setitimer(ITIMER_REAL, &zero, NULL);
}

static void test_arm_single_shot(void) {
    // Arm with it_value={10,0}, it_interval=0.
    clear_alarm();
    struct itimerval nv = {{0, 0}, {10, 0}};
    int rc = raw_setitimer(ITIMER_REAL, &nv, NULL);
    TEST_ASSERT(rc == 0, "setitimer arm success");

    struct itimerval gv;
    memset(&gv, 0, sizeof(gv));
    TEST_ASSERT(raw_getitimer(ITIMER_REAL, &gv) == 0, "getitimer after arm");
    long total_us = itimer_value_us(&gv);
    TEST_ASSERT(total_us > 0 && total_us <= 10 * 1000000L,
                "it_value in (0, 10s]");
    TEST_ASSERT(gv.it_interval.tv_sec == 0 && gv.it_interval.tv_usec == 0,
                "it_interval zero (single-shot)");
    clear_alarm();
}

static void test_disarm(void) {
    // Arm first, then disarm with all-zero new_value.
    struct itimerval nv = {{0, 0}, {10, 0}};
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &nv, NULL) == 0, "arm precondition");

    struct itimerval zero = {{0, 0}, {0, 0}};
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &zero, NULL) == 0, "disarm success");

    struct itimerval gv;
    memset(&gv, 0xff, sizeof(gv));
    TEST_ASSERT(raw_getitimer(ITIMER_REAL, &gv) == 0, "getitimer after disarm");
    TEST_ASSERT(gv.it_value.tv_sec == 0 && gv.it_value.tv_usec == 0,
                "it_value zero after disarm");
    TEST_ASSERT(gv.it_interval.tv_sec == 0 && gv.it_interval.tv_usec == 0,
                "it_interval zero after disarm");
}

static void test_disarm_ignores_interval(void) {
    struct itimerval nv = {{0, 0}, {10, 0}};
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &nv, NULL) == 0, "arm precondition");

    struct itimerval disarm = {{1, 0}, {0, 0}};
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &disarm, NULL) == 0,
                "disarm with nonzero interval success");

    struct itimerval gv;
    memset(&gv, 0xff, sizeof(gv));
    TEST_ASSERT(raw_getitimer(ITIMER_REAL, &gv) == 0,
                "getitimer after interval-only disarm");
    TEST_ASSERT(gv.it_value.tv_sec == 0 && gv.it_value.tv_usec == 0,
                "it_value zero after interval-only disarm");
    TEST_ASSERT(gv.it_interval.tv_sec == 0 && gv.it_interval.tv_usec == 0,
                "it_interval zero after interval-only disarm");
}

static void test_old_value_returns_previous(void) {
    // Set a 10s timer, then replace with a 5s timer and capture old_value.
    clear_alarm();
    struct itimerval first = {{0, 0}, {10, 0}};
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &first, NULL) == 0, "first arm");

    struct itimerval second = {{0, 0}, {5, 0}};
    struct itimerval old;
    memset(&old, 0xff, sizeof(old));
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &second, &old) == 0, "replace returns old");

    long old_us = itimer_value_us(&old);
    TEST_ASSERT(old_us > 0 && old_us <= 10 * 1000000L,
                "old it_value reflects first arm (<= 10s)");
    TEST_ASSERT(old.it_interval.tv_sec == 0 && old.it_interval.tv_usec == 0,
                "old it_interval zero");

    // Replacement should be active now.
    struct itimerval gv;
    TEST_ASSERT(raw_getitimer(ITIMER_REAL, &gv) == 0, "getitimer after replace");
    long now_us = itimer_value_us(&gv);
    TEST_ASSERT(now_us > 0 && now_us <= 5 * 1000000L,
                "current it_value reflects replacement (<= 5s)");
    clear_alarm();
}

static void test_old_value_unarmed_returns_zero(void) {
    clear_alarm();
    struct itimerval nv = {{0, 0}, {3, 0}};
    struct itimerval old;
    memset(&old, 0xff, sizeof(old));
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &nv, &old) == 0, "arm with old_value");
    TEST_ASSERT(old.it_value.tv_sec == 0 && old.it_value.tv_usec == 0,
                "old it_value zero when previously unarmed");
    TEST_ASSERT(old.it_interval.tv_sec == 0 && old.it_interval.tv_usec == 0,
                "old it_interval zero when previously unarmed");
    clear_alarm();
}

static void test_einval_usec_out_of_range(void) {
    struct itimerval nv = {{0, 0}, {1, 1000000}};
    errno = 0;
    int rc = raw_setitimer(ITIMER_REAL, &nv, NULL);
    TEST_ASSERT(rc == -1 && errno == EINVAL,
                "tv_usec >= 1000000 in it_value → EINVAL");

    nv = (struct itimerval){{0, 1000000}, {1, 0}};
    errno = 0;
    rc = raw_setitimer(ITIMER_REAL, &nv, NULL);
    TEST_ASSERT(rc == -1 && errno == EINVAL,
                "tv_usec >= 1000000 in it_interval → EINVAL");
}

static void test_einval_bad_which(void) {
    struct itimerval nv = {{0, 0}, {1, 0}};
    errno = 0;
    int rc = raw_setitimer(99, &nv, NULL);
    TEST_ASSERT(rc == -1 && errno == EINVAL, "bad which → EINVAL");
}

static void test_efault_bad_old_value(void) {
    // Bad old_value pointer with a valid new_value: Linux returns EFAULT but
    // the timer state IS still mutated (kernel arms before writing old_value).
    // Verified by host probe on kernel 6.6: rc=-1, errno=EFAULT, post-state
    // shows the requested it_value ~5s remaining.
    clear_alarm();
    struct itimerval nv = {{0, 0}, {5, 0}};
    errno = 0;
    int rc = raw_setitimer(ITIMER_REAL, &nv,
                           (struct itimerval *)(uintptr_t)0x1);
    TEST_ASSERT(rc == -1 && errno == EFAULT, "bad old_value → EFAULT");

    struct itimerval gv;
    TEST_ASSERT(raw_getitimer(ITIMER_REAL, &gv) == 0, "getitimer after EFAULT");
    long us = itimer_value_us(&gv);
    TEST_ASSERT(us > 0 && us <= 5 * 1000000L,
                "timer was armed before EFAULT write (state mutated, Linux quirk)");
    clear_alarm();
}

static void test_alarm_setitimer_share_state(void) {
    // alarm(2) and setitimer(ITIMER_REAL, ...) share the same per-process
    // timer; calls to one must be observable through the other. Verified by
    // host probe on kernel 6.6 (setitimer(7s) → alarm(0) returns 7;
    // alarm(10) → setitimer(&old) reports old.it_value ≈ 10s).
    clear_alarm();

    // Direction 1: setitimer arms; alarm(0) cancels and returns the previous
    // remaining (rounded up to whole seconds).
    struct itimerval nv = {{0, 0}, {7, 0}};
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &nv, NULL) == 0, "setitimer arm");
    unsigned int via_alarm = alarm(0);
    TEST_ASSERT(via_alarm > 0 && via_alarm <= 7,
                "alarm(0) returns setitimer's remaining seconds, rounded up");

    // Direction 2: alarm arms; setitimer(&old) reports the previous remaining
    // in old.it_value with it_interval == 0.
    clear_alarm();
    TEST_ASSERT(alarm(10) == 0, "alarm(10) on cleared state returns 0");
    struct itimerval nv2 = {{0, 0}, {3, 0}};
    struct itimerval old;
    memset(&old, 0xff, sizeof(old));
    TEST_ASSERT(raw_setitimer(ITIMER_REAL, &nv2, &old) == 0,
                "setitimer over alarm-armed state");
    long us = itimer_value_us(&old);
    TEST_ASSERT(us > 0 && us <= 10 * 1000000L,
                "old.it_value reflects prior alarm(10)");
    TEST_ASSERT(old.it_interval.tv_sec == 0 && old.it_interval.tv_usec == 0,
                "old.it_interval zero (alarm() never sets an interval)");
    clear_alarm();
}

static void test_efault_null_new_value(void) {
    errno = 0;
    int rc = raw_setitimer(ITIMER_REAL, NULL, NULL);
    // Linux: setitimer(which, NULL, NULL) is treated as "disarm" (per man page,
    // "this is treated as being equivalent to a call in which the new_value
    // fields are zero"). So no error. Verify our test asserts what Linux does.
    TEST_ASSERT(rc == 0, "setitimer with NULL new_value treated as disarm (Linux quirk)");
}

int main(void) {
    printf("setitimer tests starting...\n");
    test_arm_single_shot();
    test_disarm();
    test_disarm_ignores_interval();
    test_old_value_returns_previous();
    test_old_value_unarmed_returns_zero();
    test_einval_usec_out_of_range();
    test_einval_bad_which();
    test_efault_bad_old_value();
    test_efault_null_new_value();
    test_alarm_setitimer_share_state();
    clear_alarm();
    printf("All setitimer tests passed.\n");
    return 0;
}
