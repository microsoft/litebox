// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: getrusage, getrlimit, setrlimit, prlimit
// Resource usage and limits

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_getrusage(void) {
    // getrusage is not implemented in LiteBox
    printf("getrusage: SKIPPED (not implemented)\n");
    return 0;
}

int test_getrlimit(void) {
    struct rlimit rlim;

    // Get stack limit
    int ret = getrlimit(RLIMIT_STACK, &rlim);
    TEST_ASSERT(ret == 0, "getrlimit RLIMIT_STACK failed");
    TEST_ASSERT(rlim.rlim_cur > 0, "stack limit should be > 0");

    // Get open files limit
    ret = getrlimit(RLIMIT_NOFILE, &rlim);
    TEST_ASSERT(ret == 0, "getrlimit RLIMIT_NOFILE failed");
    TEST_ASSERT(rlim.rlim_cur > 0, "nofile limit should be > 0");

    printf("getrlimit: PASS\n");
    return 0;
}

int test_setrlimit(void) {
    struct rlimit rlim, new_rlim;

    // Get current limit
    int ret = getrlimit(RLIMIT_NOFILE, &rlim);
    TEST_ASSERT(ret == 0, "getrlimit failed");

    // Try to set a lower soft limit (should succeed)
    new_rlim.rlim_cur = rlim.rlim_cur > 64 ? 64 : rlim.rlim_cur;
    new_rlim.rlim_max = rlim.rlim_max;

    ret = setrlimit(RLIMIT_NOFILE, &new_rlim);
    TEST_ASSERT(ret == 0, "setrlimit failed");

    // Verify change
    ret = getrlimit(RLIMIT_NOFILE, &rlim);
    TEST_ASSERT(ret == 0, "getrlimit after set failed");
    TEST_ASSERT(rlim.rlim_cur == new_rlim.rlim_cur, "limit not changed");

    printf("setrlimit: PASS\n");
    return 0;
}

int test_prlimit(void) {
    struct rlimit rlim;

    // Get limit for self (pid=0)
    int ret = prlimit(0, RLIMIT_STACK, NULL, &rlim);
    TEST_ASSERT(ret == 0, "prlimit get failed");
    TEST_ASSERT(rlim.rlim_cur > 0, "stack limit should be > 0");

    printf("prlimit: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting resource limit tests...\n");

    if (test_getrusage() != 0) return 1;
    if (test_getrlimit() != 0) return 1;
    if (test_setrlimit() != 0) return 1;
    if (test_prlimit() != 0) return 1;

    printf("All resource limit tests passed!\n");
    return 0;
}
