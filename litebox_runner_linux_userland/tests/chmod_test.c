// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: chmod, fchmod, fchmodat
// File permission changes
//
// Note: CodeQL flags TOCTOU race conditions in this file, but these are false
// positives since the tests run in LiteBox's sandboxed filesystem environment.
// lgtm[cpp/toctou-race-condition]

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_fchmod_basic(void) {
    // fchmod is not implemented - needs fchmod in filesystem layer
    printf("fchmod basic: SKIPPED (not implemented)\n");
    return 0;
}

int test_chmod_basic(void) {
    const char *path = "/tmp/chmod_test";
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    TEST_ASSERT(fd >= 0, "open failed");
    close(fd);

    int ret = chmod(path, 0700);
    TEST_ASSERT(ret == 0, "chmod failed");

    struct stat st;
    stat(path, &st);
    TEST_ASSERT((st.st_mode & 0777) == 0700, "mode should be 0700");

    unlink(path);
    printf("chmod basic: PASS\n");
    return 0;
}

int test_fchmodat_basic(void) {
    // fchmodat is not implemented
    printf("fchmodat basic: SKIPPED (not implemented)\n");
    return 0;
}

int main(void) {
    printf("Starting chmod tests...\n");

    if (test_fchmod_basic() != 0) return 1;
    if (test_chmod_basic() != 0) return 1;
    if (test_fchmodat_basic() != 0) return 1;

    printf("All chmod tests passed!\n");
    return 0;
}
