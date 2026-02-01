// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: truncate, ftruncate
// File size manipulation
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
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_ftruncate_shrink(void) {
    const char *path = "/tmp/ftruncate_shrink";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    // Write some data
    const char *data = "Hello, World! This is a test.";
    write(fd, data, strlen(data));

    // Truncate to 5 bytes
    int ret = ftruncate(fd, 5);
    TEST_ASSERT(ret == 0, "ftruncate shrink failed");

    // Check size
    struct stat st;
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 5, "size should be 5");

    // Read and verify content
    lseek(fd, 0, SEEK_SET);
    char buf[16] = {0};
    read(fd, buf, 5);
    TEST_ASSERT(strncmp(buf, "Hello", 5) == 0, "content should be preserved");

    close(fd);
    unlink(path);
    printf("ftruncate shrink: PASS\n");
    return 0;
}

int test_ftruncate_extend(void) {
    const char *path = "/tmp/ftruncate_extend";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    write(fd, "ABC", 3);

    // Extend to 10 bytes
    int ret = ftruncate(fd, 10);
    TEST_ASSERT(ret == 0, "ftruncate extend failed");

    struct stat st;
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 10, "size should be 10");

    // Extended bytes should be zero
    lseek(fd, 3, SEEK_SET);
    char buf[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    read(fd, buf, 7);
    for (int i = 0; i < 7; i++) {
        TEST_ASSERT(buf[i] == 0, "extended bytes should be zero");
    }

    close(fd);
    unlink(path);
    printf("ftruncate extend: PASS\n");
    return 0;
}

// NOTE: truncate(path, len) syscall is NOW SUPPORTED in LiteBox
int test_truncate_path(void) {
    const char *path = "/tmp/truncate_path_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");
    write(fd, "Hello World!", 12);
    close(fd);

    // Truncate by path
    int ret = truncate(path, 5);
    TEST_ASSERT(ret == 0, "truncate(path) failed");

    // Verify size
    struct stat st;
    stat(path, &st);
    TEST_ASSERT(st.st_size == 5, "size should be 5");

    unlink(path);
    printf("truncate path: PASS\n");
    return 0;
}

int test_ftruncate_zero(void) {
    const char *path = "/tmp/ftruncate_zero";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "data", 4);

    int ret = ftruncate(fd, 0);
    TEST_ASSERT(ret == 0, "ftruncate to 0 failed");

    struct stat st;
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 0, "size should be 0");

    close(fd);
    unlink(path);
    printf("ftruncate zero: PASS\n");
    return 0;
}

int test_ftruncate_ebadf(void) {
    int ret = ftruncate(-1, 10);
    TEST_ASSERT(ret == -1 && errno == EBADF, "ftruncate(-1) should return EBADF");

    const char *path = "/tmp/ftruncate_rdonly";
    int fd = open(path, O_CREAT | O_RDONLY, 0644);
    ret = ftruncate(fd, 10);
    // Linux returns EINVAL, but EACCES/EPERM are also reasonable
    TEST_ASSERT(ret == -1, "ftruncate on O_RDONLY should fail");
    close(fd);
    unlink(path);

    printf("ftruncate errors: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting truncate tests...\n");

    if (test_ftruncate_shrink() != 0) return 1;
    if (test_ftruncate_extend() != 0) return 1;
    if (test_truncate_path() != 0) return 1;
    if (test_ftruncate_zero() != 0) return 1;
    if (test_ftruncate_ebadf() != 0) return 1;

    printf("All truncate tests passed!\n");
    return 0;
}
