// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: fsync, fdatasync, sync
// These are commonly needed for database applications

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 1; \
    } \
} while(0)

int test_fsync_basic(void) {
    const char *path = "/tmp/test_fsync";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    const char *data = "test data for sync operations";
    ssize_t written = write(fd, data, strlen(data));
    TEST_ASSERT(written == (ssize_t)strlen(data), "write failed");

    // Test fsync
    int ret = fsync(fd);
    TEST_ASSERT(ret == 0, "fsync failed");
    printf("fsync: PASS\n");

    // Write more data
    written = write(fd, data, strlen(data));
    TEST_ASSERT(written == (ssize_t)strlen(data), "second write failed");

    // Test fdatasync
    ret = fdatasync(fd);
    TEST_ASSERT(ret == 0, "fdatasync failed");
    printf("fdatasync: PASS\n");

    close(fd);
    unlink(path);
    return 0;
}

int test_fsync_ebadf(void) {
    // fsync on invalid fd should return EBADF
    int ret = fsync(-1);
    TEST_ASSERT(ret == -1 && errno == EBADF, "fsync(-1) should return EBADF");
    printf("fsync EBADF: PASS\n");
    return 0;
}

int test_sync(void) {
    // sync() always succeeds (returns void in POSIX, 0 in Linux)
    sync();
    printf("sync: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting fsync tests...\n");

    if (test_fsync_basic() != 0) return 1;
    if (test_fsync_ebadf() != 0) return 1;
    if (test_sync() != 0) return 1;

    printf("All fsync tests passed!\n");
    return 0;
}
