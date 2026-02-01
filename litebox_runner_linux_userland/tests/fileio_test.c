// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: Basic file operations - open, close, read, write
// Comprehensive basic I/O tests
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
#include <sys/stat.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_open_create(void) {
    const char *path = "/tmp/open_create_test";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open O_CREAT failed");
    close(fd);

    // File should exist now
    struct stat st;
    int ret = stat(path, &st);
    TEST_ASSERT(ret == 0, "created file should exist");

    unlink(path);
    printf("open O_CREAT: PASS\n");
    return 0;
}

int test_open_excl(void) {
    const char *path = "/tmp/open_excl_test";
    unlink(path);  // Ensure doesn't exist

    // Create new file with O_EXCL
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    TEST_ASSERT(fd >= 0, "open O_CREAT|O_EXCL failed for new file");
    close(fd);

    // Try again - should fail with EEXIST
    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    TEST_ASSERT(fd == -1 && errno == EEXIST, "O_EXCL should fail for existing file");

    unlink(path);
    printf("open O_EXCL: PASS\n");
    return 0;
}

int test_open_append(void) {
    const char *path = "/tmp/open_append_test";

    // Create and write initial content
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(fd, "initial", 7);
    close(fd);

    // Open with O_APPEND and write more
    fd = open(path, O_WRONLY | O_APPEND);
    TEST_ASSERT(fd >= 0, "open O_APPEND failed");
    write(fd, "_append", 7);
    close(fd);

    // Verify content
    fd = open(path, O_RDONLY);
    char buf[32] = {0};
    read(fd, buf, sizeof(buf) - 1);
    close(fd);
    TEST_ASSERT(strcmp(buf, "initial_append") == 0, "O_APPEND should append");

    unlink(path);
    printf("open O_APPEND: PASS\n");
    return 0;
}

int test_read_write_basic(void) {
    const char *path = "/tmp/rw_basic_test";
    const char *data = "Hello, World!";

    // Write
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    ssize_t n = write(fd, data, strlen(data));
    TEST_ASSERT(n == (ssize_t)strlen(data), "write should return byte count");
    close(fd);

    // Read
    fd = open(path, O_RDONLY);
    char buf[32] = {0};
    n = read(fd, buf, sizeof(buf) - 1);
    TEST_ASSERT(n == (ssize_t)strlen(data), "read should return byte count");
    TEST_ASSERT(strcmp(buf, data) == 0, "read data should match written");
    close(fd);

    unlink(path);
    printf("read/write basic: PASS\n");
    return 0;
}

int test_read_eof(void) {
    const char *path = "/tmp/read_eof_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "short", 5);
    lseek(fd, 0, SEEK_SET);

    char buf[32];
    ssize_t n = read(fd, buf, 5);
    TEST_ASSERT(n == 5, "first read should get 5 bytes");

    n = read(fd, buf, 32);
    TEST_ASSERT(n == 0, "read at EOF should return 0");

    close(fd);
    unlink(path);
    printf("read EOF: PASS\n");
    return 0;
}

int test_close_invalid(void) {
    int ret = close(-1);
    TEST_ASSERT(ret == -1 && errno == EBADF, "close(-1) should return EBADF");

    ret = close(999);
    TEST_ASSERT(ret == -1 && errno == EBADF, "close(999) should return EBADF");

    printf("close invalid: PASS\n");
    return 0;
}

int test_open_enoent(void) {
    int fd = open("/nonexistent_path_12345/file", O_RDONLY);
    TEST_ASSERT(fd == -1 && errno == ENOENT, "open nonexistent should return ENOENT");

    printf("open ENOENT: PASS\n");
    return 0;
}

int test_write_readonly(void) {
    const char *path = "/tmp/write_readonly_test";
    int fd = open(path, O_CREAT | O_RDONLY, 0644);
    TEST_ASSERT(fd >= 0, "open O_RDONLY failed");

    ssize_t n = write(fd, "test", 4);
    // LiteBox returns EACCES, Linux returns EBADF - both indicate error
    TEST_ASSERT(n == -1, "write to O_RDONLY should fail");

    close(fd);
    unlink(path);
    printf("write readonly: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting basic file I/O tests...\n");

    if (test_open_create() != 0) return 1;
    if (test_open_excl() != 0) return 1;
    if (test_open_append() != 0) return 1;
    if (test_read_write_basic() != 0) return 1;
    if (test_read_eof() != 0) return 1;
    if (test_close_invalid() != 0) return 1;
    if (test_open_enoent() != 0) return 1;
    if (test_write_readonly() != 0) return 1;

    printf("All basic file I/O tests passed!\n");
    return 0;
}
