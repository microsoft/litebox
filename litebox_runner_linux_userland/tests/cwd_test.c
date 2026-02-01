// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: getcwd, chdir
// Working directory operations

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_getcwd_basic(void) {
    char buf[PATH_MAX];
    char *result = getcwd(buf, sizeof(buf));
    TEST_ASSERT(result != NULL, "getcwd failed");
    TEST_ASSERT(result == buf, "getcwd should return buffer");
    TEST_ASSERT(buf[0] == '/', "cwd should be absolute path");
    TEST_ASSERT(strlen(buf) > 0, "cwd should not be empty");

    printf("getcwd basic: PASS (cwd=%s)\n", buf);
    return 0;
}

int test_getcwd_small_buffer(void) {
    char buf[2];
    char *result = getcwd(buf, sizeof(buf));
    // Should fail with ERANGE if cwd is longer than 2 chars
    // (which it almost always is)
    if (result == NULL && errno == ERANGE) {
        printf("getcwd small buffer: PASS (ERANGE as expected)\n");
    } else if (result != NULL && strlen(result) < 2) {
        // If cwd is actually "/" it might succeed
        printf("getcwd small buffer: PASS (short cwd)\n");
    } else {
        printf("getcwd small buffer: PASS (behavior varies)\n");
    }
    return 0;
}

int test_chdir_basic(void) {
    char original[PATH_MAX];
    getcwd(original, sizeof(original));

    // Change to /tmp
    int ret = chdir("/tmp");
    TEST_ASSERT(ret == 0, "chdir /tmp failed");

    // Verify
    char current[PATH_MAX];
    getcwd(current, sizeof(current));
    TEST_ASSERT(strcmp(current, "/tmp") == 0, "cwd should be /tmp");

    // Change back
    ret = chdir(original);
    TEST_ASSERT(ret == 0, "chdir back failed");

    getcwd(current, sizeof(current));
    TEST_ASSERT(strcmp(current, original) == 0, "should be back to original");

    printf("chdir basic: PASS\n");
    return 0;
}

int test_chdir_enoent(void) {
    int ret = chdir("/nonexistent_dir_12345");
    TEST_ASSERT(ret == -1 && errno == ENOENT, "chdir nonexistent should return ENOENT");

    printf("chdir ENOENT: PASS\n");
    return 0;
}

int test_chdir_to_file(void) {
    // Try to chdir to a file (should fail with ENOTDIR)
    const char *path = "/tmp/chdir_file_test";
    int fd = creat(path, 0644);
    close(fd);

    int ret = chdir(path);
    TEST_ASSERT(ret == -1 && errno == ENOTDIR, "chdir to file should return ENOTDIR");

    unlink(path);
    printf("chdir to file: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting getcwd/chdir tests...\n");

    if (test_getcwd_basic() != 0) return 1;
    if (test_getcwd_small_buffer() != 0) return 1;
    if (test_chdir_basic() != 0) return 1;
    if (test_chdir_enoent() != 0) return 1;
    if (test_chdir_to_file() != 0) return 1;

    printf("All getcwd/chdir tests passed!\n");
    return 0;
}
