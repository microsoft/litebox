// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: uname
// System information

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <string.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_uname_basic(void) {
    struct utsname buf;
    int ret = uname(&buf);
    TEST_ASSERT(ret == 0, "uname failed");

    // All fields should be non-empty strings
    TEST_ASSERT(strlen(buf.sysname) > 0, "sysname should not be empty");
    TEST_ASSERT(strlen(buf.nodename) > 0, "nodename should not be empty");
    TEST_ASSERT(strlen(buf.release) > 0, "release should not be empty");
    TEST_ASSERT(strlen(buf.version) > 0, "version should not be empty");
    TEST_ASSERT(strlen(buf.machine) > 0, "machine should not be empty");

    printf("uname basic: PASS\n");
    printf("  sysname: %s\n", buf.sysname);
    printf("  release: %s\n", buf.release);
    printf("  machine: %s\n", buf.machine);
    return 0;
}

int test_uname_sysname(void) {
    struct utsname buf;
    uname(&buf);

    // LiteBox reports "LiteBox" not "Linux" - this is expected
    // The test just verifies the sysname is set to something reasonable
    TEST_ASSERT(strlen(buf.sysname) > 0, "sysname should not be empty");

    printf("uname sysname: PASS (sysname=%s)\n", buf.sysname);
    return 0;
}

int test_uname_consistency(void) {
    struct utsname buf1, buf2;
    uname(&buf1);
    uname(&buf2);

    // Should return same values
    TEST_ASSERT(strcmp(buf1.sysname, buf2.sysname) == 0, "sysname should be consistent");
    TEST_ASSERT(strcmp(buf1.release, buf2.release) == 0, "release should be consistent");
    TEST_ASSERT(strcmp(buf1.machine, buf2.machine) == 0, "machine should be consistent");

    printf("uname consistency: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting uname tests...\n");

    if (test_uname_basic() != 0) return 1;
    if (test_uname_sysname() != 0) return 1;
    if (test_uname_consistency() != 0) return 1;

    printf("All uname tests passed!\n");
    return 0;
}
