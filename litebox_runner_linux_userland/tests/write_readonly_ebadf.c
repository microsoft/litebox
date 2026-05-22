// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: write(2), pwrite(2), writev(2), pwritev(2) all return EBADF when
// invoked on a read-only fd, matching Linux's write(2) man page semantics
// for "fd not open for writing".

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#define FAIL(msg)                                                              \
    do {                                                                       \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d: %s)\n", __func__,   \
                __LINE__, (msg), errno, strerror(errno));                      \
        exit(1);                                                               \
    } while (0)

#define EXPECT(cond, msg)                                                      \
    do {                                                                       \
        if (!(cond)) {                                                         \
            FAIL(msg);                                                         \
        }                                                                      \
    } while (0)

static int open_readonly(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open rw for setup failed");
    EXPECT(write(fd, "x", 1) == 1, "setup write failed");
    EXPECT(close(fd) == 0, "setup close failed");

    fd = open(path, O_RDONLY);
    EXPECT(fd >= 0, "reopen read-only failed");
    return fd;
}

static void test_write_readonly_ebadf(void) {
    const char *path = "/tmp/test_write_ro.bin";
    int fd = open_readonly(path);

    errno = 0;
    ssize_t n = write(fd, "data", 4);
    EXPECT(n == -1 && errno == EBADF,
           "write on read-only fd should fail with EBADF");

    close(fd);
    unlink(path);
}

static void test_pwrite_readonly_ebadf(void) {
    const char *path = "/tmp/test_pwrite_ro.bin";
    int fd = open_readonly(path);

    errno = 0;
    ssize_t n = pwrite(fd, "data", 4, 0);
    EXPECT(n == -1 && errno == EBADF,
           "pwrite on read-only fd should fail with EBADF");

    close(fd);
    unlink(path);
}

static void test_writev_readonly_ebadf(void) {
    const char *path = "/tmp/test_writev_ro.bin";
    int fd = open_readonly(path);

    char buf[4] = "data";
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};
    errno = 0;
    ssize_t n = writev(fd, iov, 1);
    EXPECT(n == -1 && errno == EBADF,
           "writev on read-only fd should fail with EBADF");

    close(fd);
    unlink(path);
}

int main(void) {
    printf("===== write-on-readonly-fd EBADF tests =====\n");
    test_write_readonly_ebadf();
    test_pwrite_readonly_ebadf();
    test_writev_readonly_ebadf();
    printf("All write-on-readonly EBADF tests passed.\n");
    return 0;
}
