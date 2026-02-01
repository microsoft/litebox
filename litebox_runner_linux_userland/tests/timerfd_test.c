// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: timerfd_create, timerfd_settime, timerfd_gettime
// Timer file descriptors - commonly used in event loops

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <stdint.h>
#include <errno.h>
#include <poll.h>
#include <time.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_timerfd_create(void) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    TEST_ASSERT(tfd >= 0, "timerfd_create failed");
    close(tfd);

    tfd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
    TEST_ASSERT(tfd >= 0, "timerfd_create with flags failed");
    close(tfd);

    printf("timerfd_create: PASS\n");
    return 0;
}

int test_timerfd_oneshot(void) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    TEST_ASSERT(tfd >= 0, "timerfd_create failed");

    struct itimerspec its = {
        .it_value = { .tv_sec = 0, .tv_nsec = 50000000 },  // 50ms
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 }       // one-shot
    };

    int ret = timerfd_settime(tfd, 0, &its, NULL);
    TEST_ASSERT(ret == 0, "timerfd_settime failed");

    // Wait for timer with poll
    struct pollfd pfd = { .fd = tfd, .events = POLLIN };
    ret = poll(&pfd, 1, 200);  // 200ms timeout
    TEST_ASSERT(ret == 1, "poll should return when timer fires");

    // Read expiration count
    uint64_t expirations;
    ssize_t n = read(tfd, &expirations, sizeof(expirations));
    TEST_ASSERT(n == sizeof(expirations), "read from timerfd failed");
    TEST_ASSERT(expirations >= 1, "should have at least 1 expiration");

    close(tfd);
    printf("timerfd oneshot: PASS\n");
    return 0;
}

int test_timerfd_gettime(void) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    TEST_ASSERT(tfd >= 0, "timerfd_create failed");

    struct itimerspec its = {
        .it_value = { .tv_sec = 10, .tv_nsec = 0 },    // 10 seconds
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 }   // 1 second interval
    };

    int ret = timerfd_settime(tfd, 0, &its, NULL);
    TEST_ASSERT(ret == 0, "timerfd_settime failed");

    struct itimerspec curr;
    ret = timerfd_gettime(tfd, &curr);
    TEST_ASSERT(ret == 0, "timerfd_gettime failed");

    // Value should be close to 10 seconds (allowing for some time passing)
    TEST_ASSERT(curr.it_value.tv_sec >= 9, "remaining time should be ~10s");
    TEST_ASSERT(curr.it_interval.tv_sec == 1, "interval should be 1s");

    close(tfd);
    printf("timerfd_gettime: PASS\n");
    return 0;
}

int test_timerfd_disarm(void) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    TEST_ASSERT(tfd >= 0, "timerfd_create failed");

    // Arm the timer
    struct itimerspec its = {
        .it_value = { .tv_sec = 1, .tv_nsec = 0 },
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 }
    };
    timerfd_settime(tfd, 0, &its, NULL);

    // Disarm by setting to zero
    struct itimerspec disarm = { 0 };
    int ret = timerfd_settime(tfd, 0, &disarm, NULL);
    TEST_ASSERT(ret == 0, "disarm failed");

    // Verify disarmed
    struct itimerspec curr;
    timerfd_gettime(tfd, &curr);
    TEST_ASSERT(curr.it_value.tv_sec == 0 && curr.it_value.tv_nsec == 0,
                "timer should be disarmed");

    close(tfd);
    printf("timerfd disarm: PASS\n");
    return 0;
}

int test_timerfd_periodic(void) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    TEST_ASSERT(tfd >= 0, "timerfd_create failed");

    // Set a periodic timer: 20ms initial, 20ms interval
    struct itimerspec its = {
        .it_value = { .tv_sec = 0, .tv_nsec = 20000000 },     // 20ms
        .it_interval = { .tv_sec = 0, .tv_nsec = 20000000 }   // 20ms
    };

    int ret = timerfd_settime(tfd, 0, &its, NULL);
    TEST_ASSERT(ret == 0, "timerfd_settime failed");

    // Wait 100ms to allow multiple expirations
    usleep(100000);

    // Read expiration count - should have accumulated multiple expirations
    uint64_t expirations;
    ssize_t n = read(tfd, &expirations, sizeof(expirations));
    TEST_ASSERT(n == sizeof(expirations), "read from timerfd failed");
    // With 20ms interval and 100ms wait, expect ~4-5 expirations
    // Use >= 3 to account for timing variations
    TEST_ASSERT(expirations >= 3, "should have multiple expirations for periodic timer");

    // Verify interval is still set
    struct itimerspec curr;
    timerfd_gettime(tfd, &curr);
    TEST_ASSERT(curr.it_interval.tv_nsec == 20000000, "interval should still be 20ms");

    close(tfd);
    printf("timerfd periodic: PASS (expirations=%lu)\n", (unsigned long)expirations);
    return 0;
}

int main(void) {
    printf("Starting timerfd tests...\n");

    if (test_timerfd_create() != 0) return 1;
    if (test_timerfd_oneshot() != 0) return 1;
    if (test_timerfd_gettime() != 0) return 1;
    if (test_timerfd_disarm() != 0) return 1;
    if (test_timerfd_periodic() != 0) return 1;

    printf("All timerfd tests passed!\n");
    return 0;
}
