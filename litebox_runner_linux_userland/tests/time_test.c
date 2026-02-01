// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: clock_gettime, clock_getres, gettimeofday
// Time syscalls

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_clock_gettime_realtime(void) {
    struct timespec ts;
    int ret = clock_gettime(CLOCK_REALTIME, &ts);
    TEST_ASSERT(ret == 0, "clock_gettime CLOCK_REALTIME failed");
    TEST_ASSERT(ts.tv_sec > 0, "time should be positive");
    TEST_ASSERT(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000, "nsec in valid range");

    printf("clock_gettime REALTIME: PASS (time=%ld.%09ld)\n", ts.tv_sec, ts.tv_nsec);
    return 0;
}

int test_clock_gettime_monotonic(void) {
    struct timespec ts1, ts2;

    int ret = clock_gettime(CLOCK_MONOTONIC, &ts1);
    TEST_ASSERT(ret == 0, "clock_gettime CLOCK_MONOTONIC failed");

    // Small busy wait
    for (volatile int i = 0; i < 100000; i++);

    ret = clock_gettime(CLOCK_MONOTONIC, &ts2);
    TEST_ASSERT(ret == 0, "second clock_gettime failed");

    // Monotonic should not go backwards
    long diff_ns = (ts2.tv_sec - ts1.tv_sec) * 1000000000L + (ts2.tv_nsec - ts1.tv_nsec);
    TEST_ASSERT(diff_ns >= 0, "monotonic clock should not go backwards");

    printf("clock_gettime MONOTONIC: PASS\n");
    return 0;
}

int test_clock_getres(void) {
    struct timespec res;
    int ret = clock_getres(CLOCK_REALTIME, &res);
    TEST_ASSERT(ret == 0, "clock_getres CLOCK_REALTIME failed");
    TEST_ASSERT(res.tv_sec >= 0, "resolution should be non-negative");

    ret = clock_getres(CLOCK_MONOTONIC, &res);
    TEST_ASSERT(ret == 0, "clock_getres CLOCK_MONOTONIC failed");

    printf("clock_getres: PASS\n");
    return 0;
}

int test_gettimeofday(void) {
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    TEST_ASSERT(ret == 0, "gettimeofday failed");
    TEST_ASSERT(tv.tv_sec > 0, "time should be positive");
    TEST_ASSERT(tv.tv_usec >= 0 && tv.tv_usec < 1000000, "usec in valid range");

    printf("gettimeofday: PASS\n");
    return 0;
}

int test_nanosleep(void) {
    struct timespec req = { .tv_sec = 0, .tv_nsec = 10000000 };  // 10ms
    struct timespec rem;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int ret = nanosleep(&req, &rem);
    TEST_ASSERT(ret == 0, "nanosleep failed");

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    TEST_ASSERT(elapsed_ns >= 5000000, "should have slept at least 5ms");

    printf("nanosleep: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting time tests...\n");

    if (test_clock_gettime_realtime() != 0) return 1;
    if (test_clock_gettime_monotonic() != 0) return 1;
    if (test_clock_getres() != 0) return 1;
    if (test_gettimeofday() != 0) return 1;
    if (test_nanosleep() != 0) return 1;

    printf("All time tests passed!\n");
    return 0;
}
