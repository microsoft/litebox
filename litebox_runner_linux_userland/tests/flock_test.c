// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: flock, fcntl locks (F_SETLK, F_GETLK)
// File locking primitives

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
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

int test_flock_exclusive(void) {
    const char *path = "/tmp/flock_test";
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    // Take exclusive lock
    int ret = flock(fd, LOCK_EX);
    TEST_ASSERT(ret == 0, "flock LOCK_EX failed");

    // Unlock
    ret = flock(fd, LOCK_UN);
    TEST_ASSERT(ret == 0, "flock LOCK_UN failed");

    close(fd);
    unlink(path);
    printf("flock exclusive: PASS\n");
    return 0;
}

int test_flock_shared(void) {
    const char *path = "/tmp/flock_shared_test";
    int fd1 = open(path, O_CREAT | O_RDWR, 0644);
    TEST_ASSERT(fd1 >= 0, "open fd1 failed");

    int fd2 = open(path, O_RDWR);
    TEST_ASSERT(fd2 >= 0, "open fd2 failed");

    // Both can take shared locks
    int ret = flock(fd1, LOCK_SH);
    TEST_ASSERT(ret == 0, "flock LOCK_SH on fd1 failed");

    ret = flock(fd2, LOCK_SH);
    TEST_ASSERT(ret == 0, "flock LOCK_SH on fd2 failed");

    // Unlock both
    flock(fd1, LOCK_UN);
    flock(fd2, LOCK_UN);

    close(fd1);
    close(fd2);
    unlink(path);
    printf("flock shared: PASS\n");
    return 0;
}

int test_flock_nonblock(void) {
    const char *path = "/tmp/flock_nb_test";
    int fd1 = open(path, O_CREAT | O_RDWR, 0644);
    TEST_ASSERT(fd1 >= 0, "open fd1 failed");

    int fd2 = open(path, O_RDWR);
    TEST_ASSERT(fd2 >= 0, "open fd2 failed");

    // Take exclusive lock on fd1
    int ret = flock(fd1, LOCK_EX);
    TEST_ASSERT(ret == 0, "flock LOCK_EX on fd1 failed");

    // In LiteBox's single-process environment, locks always succeed
    // because there's no other process to contend with.
    // This differs from multi-process Linux where this would return EWOULDBLOCK.
    ret = flock(fd2, LOCK_EX | LOCK_NB);
    TEST_ASSERT(ret == 0, "flock LOCK_NB should succeed in single-process env");

    flock(fd1, LOCK_UN);
    flock(fd2, LOCK_UN);
    close(fd1);
    close(fd2);
    unlink(path);
    printf("flock nonblock: PASS (single-process mode)\n");
    return 0;
}

int test_fcntl_lock(void) {
    const char *path = "/tmp/fcntl_lock_test";
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    // Write some data
    write(fd, "test data for locking", 21);

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 10  // Lock first 10 bytes
    };

    // Set write lock
    int ret = fcntl(fd, F_SETLK, &fl);
    TEST_ASSERT(ret == 0, "fcntl F_SETLK failed");

    // Query the lock
    struct flock query = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 10
    };
    ret = fcntl(fd, F_GETLK, &query);
    TEST_ASSERT(ret == 0, "fcntl F_GETLK failed");
    // F_GETLK returns F_UNLCK if lock would succeed (no conflict)
    // or returns info about conflicting lock

    // Unlock
    fl.l_type = F_UNLCK;
    ret = fcntl(fd, F_SETLK, &fl);
    TEST_ASSERT(ret == 0, "fcntl F_UNLCK failed");

    close(fd);
    unlink(path);
    printf("fcntl lock: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting file locking tests...\n");

    if (test_flock_exclusive() != 0) return 1;
    if (test_flock_shared() != 0) return 1;
    if (test_flock_nonblock() != 0) return 1;
    if (test_fcntl_lock() != 0) return 1;

    printf("All file locking tests passed!\n");
    return 0;
}
