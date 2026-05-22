// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: readv/writev/preadv/pwritev reject iovcnt > IOV_MAX (1024) and
// negative iovcnt with EINVAL, matching Linux's documented behavior. The
// boundary value IOV_MAX itself must still succeed.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
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

// Linux documents IOV_MAX as 1024 in <limits.h>; the kernel's UIO_MAXIOV
// matches. Use the constant rather than the header value so the test asserts
// the documented Linux contract even if a vendor's limits.h drifts.
#define LB_IOV_MAX 1024

static ssize_t raw_preadv(int fd, const struct iovec *iov, long iovcnt,
                          off_t offset) {
    return syscall(SYS_preadv, (long)fd, iov, iovcnt, (long)offset, 0L);
}

static ssize_t raw_pwritev(int fd, const struct iovec *iov, long iovcnt,
                           off_t offset) {
    return syscall(SYS_pwritev, (long)fd, iov, iovcnt, (long)offset, 0L);
}

static ssize_t raw_readv(int fd, const struct iovec *iov, long iovcnt) {
    return syscall(SYS_readv, (long)fd, iov, iovcnt);
}

static ssize_t raw_writev(int fd, const struct iovec *iov, long iovcnt) {
    return syscall(SYS_writev, (long)fd, iov, iovcnt);
}

// A 1025-entry iov array pointing into a single byte. Sizes are 1 so the
// boundary call (iovcnt == IOV_MAX) succeeds with a small total transfer.
static char iov_byte;
static struct iovec iov_array[LB_IOV_MAX + 1];

static void seed_iov_array(void) {
    for (size_t i = 0; i < sizeof(iov_array) / sizeof(iov_array[0]); i++) {
        iov_array[i].iov_base = &iov_byte;
        iov_array[i].iov_len = 1;
    }
}

static int open_seeded(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open test file failed");
    // Seed at least IOV_MAX bytes so the boundary readv/preadv has data to read.
    char buf[LB_IOV_MAX];
    memset(buf, 'A', sizeof(buf));
    EXPECT(write(fd, buf, sizeof(buf)) == (ssize_t)sizeof(buf),
           "seed write failed");
    EXPECT(lseek(fd, 0, SEEK_SET) == 0, "seed rewind failed");
    return fd;
}

static void test_readv(void) {
    const char *path = "/tmp/test_iov_max_readv.bin";
    int fd = open_seeded(path);

    errno = 0;
    EXPECT(raw_readv(fd, iov_array, LB_IOV_MAX + 1) == -1 && errno == EINVAL,
           "readv with iovcnt > IOV_MAX should fail with EINVAL");

    errno = 0;
    EXPECT(raw_readv(fd, iov_array, -1) == -1 && errno == EINVAL,
           "readv with negative iovcnt should fail with EINVAL");

    EXPECT(lseek(fd, 0, SEEK_SET) == 0, "rewind before boundary call failed");
    EXPECT(raw_readv(fd, iov_array, LB_IOV_MAX) == LB_IOV_MAX,
           "readv with iovcnt == IOV_MAX should succeed");

    close(fd);
    unlink(path);
}

static void test_writev(void) {
    const char *path = "/tmp/test_iov_max_writev.bin";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open writev test file failed");

    errno = 0;
    EXPECT(raw_writev(fd, iov_array, LB_IOV_MAX + 1) == -1 && errno == EINVAL,
           "writev with iovcnt > IOV_MAX should fail with EINVAL");

    errno = 0;
    EXPECT(raw_writev(fd, iov_array, -1) == -1 && errno == EINVAL,
           "writev with negative iovcnt should fail with EINVAL");

    EXPECT(raw_writev(fd, iov_array, LB_IOV_MAX) == LB_IOV_MAX,
           "writev with iovcnt == IOV_MAX should succeed");

    close(fd);
    unlink(path);
}

static void test_preadv(void) {
    const char *path = "/tmp/test_iov_max_preadv.bin";
    int fd = open_seeded(path);

    errno = 0;
    EXPECT(raw_preadv(fd, iov_array, LB_IOV_MAX + 1, 0) == -1 && errno == EINVAL,
           "preadv with iovcnt > IOV_MAX should fail with EINVAL");

    errno = 0;
    EXPECT(raw_preadv(fd, iov_array, -1, 0) == -1 && errno == EINVAL,
           "preadv with negative iovcnt should fail with EINVAL");

    EXPECT(raw_preadv(fd, iov_array, LB_IOV_MAX, 0) == LB_IOV_MAX,
           "preadv with iovcnt == IOV_MAX should succeed");

    close(fd);
    unlink(path);
}

static void test_pwritev(void) {
    const char *path = "/tmp/test_iov_max_pwritev.bin";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open pwritev test file failed");

    errno = 0;
    EXPECT(raw_pwritev(fd, iov_array, LB_IOV_MAX + 1, 0) == -1 &&
               errno == EINVAL,
           "pwritev with iovcnt > IOV_MAX should fail with EINVAL");

    errno = 0;
    EXPECT(raw_pwritev(fd, iov_array, -1, 0) == -1 && errno == EINVAL,
           "pwritev with negative iovcnt should fail with EINVAL");

    EXPECT(raw_pwritev(fd, iov_array, LB_IOV_MAX, 0) == LB_IOV_MAX,
           "pwritev with iovcnt == IOV_MAX should succeed");

    close(fd);
    unlink(path);
}

int main(void) {
    printf("===== iov_max tests =====\n");
    seed_iov_array();
    test_readv();
    test_writev();
    test_preadv();
    test_pwritev();
    printf("All iov_max tests passed.\n");
    return 0;
}
