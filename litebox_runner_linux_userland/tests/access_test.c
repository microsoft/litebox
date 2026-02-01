// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: access, faccessat
// File access permission checks
//
// Note: CodeQL flags TOCTOU race conditions in this file, but these are false
// positives since the tests run in LiteBox's sandboxed filesystem environment.
// lgtm[cpp/toctou-race-condition]

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_access_exists(void) {
    const char *path = "/tmp/access_test";
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    TEST_ASSERT(fd >= 0, "create file failed");
    close(fd);

    // File exists
    int ret = access(path, F_OK);
    TEST_ASSERT(ret == 0, "F_OK should succeed for existing file");

    unlink(path);

    // File doesn't exist
    ret = access(path, F_OK);
    TEST_ASSERT(ret == -1 && errno == ENOENT, "F_OK should fail for nonexistent file");

    printf("access F_OK: PASS\n");
    return 0;
}

int test_access_read(void) {
    const char *path = "/tmp/access_read_test";
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    close(fd);

    int ret = access(path, R_OK);
    TEST_ASSERT(ret == 0, "R_OK should succeed for readable file");

    unlink(path);
    printf("access R_OK: PASS\n");
    return 0;
}

int test_access_write(void) {
    const char *path = "/tmp/access_write_test";
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    close(fd);

    int ret = access(path, W_OK);
    TEST_ASSERT(ret == 0, "W_OK should succeed for writable file");

    unlink(path);
    printf("access W_OK: PASS\n");
    return 0;
}

int test_access_execute(void) {
    // /tmp should be searchable (executable for directories)
    int ret = access("/tmp", X_OK);
    TEST_ASSERT(ret == 0, "X_OK should succeed for /tmp");

    printf("access X_OK: PASS\n");
    return 0;
}

int test_access_combined(void) {
    const char *path = "/tmp/access_combined_test";
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    close(fd);

    // Check read and write together
    int ret = access(path, R_OK | W_OK);
    TEST_ASSERT(ret == 0, "R_OK|W_OK should succeed");

    unlink(path);
    printf("access combined: PASS\n");
    return 0;
}

int test_faccessat_basic(void) {
    const char *path = "/tmp/faccessat_test";
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    close(fd);

    int ret = faccessat(AT_FDCWD, path, F_OK, 0);
    TEST_ASSERT(ret == 0, "faccessat should succeed");

    unlink(path);
    printf("faccessat basic: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting access tests...\n");

    if (test_access_exists() != 0) return 1;
    if (test_access_read() != 0) return 1;
    if (test_access_write() != 0) return 1;
    if (test_access_execute() != 0) return 1;
    if (test_access_combined() != 0) return 1;
    if (test_faccessat_basic() != 0) return 1;

    printf("All access tests passed!\n");
    return 0;
}
