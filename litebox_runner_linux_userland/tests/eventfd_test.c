// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: eventfd, eventfd2
// Used for event notification between processes/threads

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <stdint.h>
#include <errno.h>
#include <poll.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_eventfd_basic(void) {
    int efd = eventfd(0, 0);
    TEST_ASSERT(efd >= 0, "eventfd failed");

    // Write a value
    uint64_t val = 42;
    ssize_t ret = write(efd, &val, sizeof(val));
    TEST_ASSERT(ret == sizeof(val), "write to eventfd failed");

    // Read the value
    uint64_t result = 0;
    ret = read(efd, &result, sizeof(result));
    TEST_ASSERT(ret == sizeof(result), "read from eventfd failed");
    TEST_ASSERT(result == 42, "eventfd value mismatch");

    close(efd);
    printf("eventfd basic: PASS\n");
    return 0;
}

int test_eventfd_accumulate(void) {
    int efd = eventfd(0, 0);
    TEST_ASSERT(efd >= 0, "eventfd failed");

    // Write multiple values - they should accumulate
    uint64_t val1 = 10;
    uint64_t val2 = 20;
    uint64_t val3 = 30;
    write(efd, &val1, sizeof(val1));
    write(efd, &val2, sizeof(val2));
    write(efd, &val3, sizeof(val3));

    // Read should return sum
    uint64_t result = 0;
    read(efd, &result, sizeof(result));
    TEST_ASSERT(result == 60, "eventfd should accumulate values");

    close(efd);
    printf("eventfd accumulate: PASS\n");
    return 0;
}

int test_eventfd_nonblock(void) {
    int efd = eventfd(0, EFD_NONBLOCK);
    TEST_ASSERT(efd >= 0, "eventfd with EFD_NONBLOCK failed");

    // Read should fail with EAGAIN when no data
    uint64_t result = 0;
    ssize_t ret = read(efd, &result, sizeof(result));
    TEST_ASSERT(ret == -1 && errno == EAGAIN, "nonblocking read should return EAGAIN");

    close(efd);
    printf("eventfd nonblock: PASS\n");
    return 0;
}

int test_eventfd_semaphore(void) {
    int efd = eventfd(3, EFD_SEMAPHORE);
    TEST_ASSERT(efd >= 0, "eventfd with EFD_SEMAPHORE failed");

    // Each read returns 1 and decrements
    uint64_t result = 0;

    read(efd, &result, sizeof(result));
    TEST_ASSERT(result == 1, "semaphore read should return 1");

    read(efd, &result, sizeof(result));
    TEST_ASSERT(result == 1, "semaphore read should return 1");

    read(efd, &result, sizeof(result));
    TEST_ASSERT(result == 1, "semaphore read should return 1");

    close(efd);
    printf("eventfd semaphore: PASS\n");
    return 0;
}

int test_eventfd_poll(void) {
    int efd = eventfd(0, EFD_NONBLOCK);
    TEST_ASSERT(efd >= 0, "eventfd failed");

    struct pollfd pfd;
    pfd.fd = efd;
    pfd.events = POLLIN;

    // Should not be readable yet
    int ret = poll(&pfd, 1, 0);
    TEST_ASSERT(ret == 0, "empty eventfd should not be readable");

    // Write something
    uint64_t val = 1;
    write(efd, &val, sizeof(val));

    // Now should be readable
    ret = poll(&pfd, 1, 0);
    TEST_ASSERT(ret == 1 && (pfd.revents & POLLIN), "eventfd should be readable after write");

    close(efd);
    printf("eventfd poll: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting eventfd tests...\n");

    if (test_eventfd_basic() != 0) return 1;
    if (test_eventfd_accumulate() != 0) return 1;
    if (test_eventfd_nonblock() != 0) return 1;
    if (test_eventfd_semaphore() != 0) return 1;
    if (test_eventfd_poll() != 0) return 1;

    printf("All eventfd tests passed!\n");
    return 0;
}
