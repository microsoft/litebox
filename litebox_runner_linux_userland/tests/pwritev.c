// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: pwritev positional vectored write.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

// The kernel's pwritev syscall takes (fd, vec, vlen, pos_l, pos_h). On 64-bit
// platforms pos_h is unused and must be 0.
static ssize_t raw_pwritev(int fd, const struct iovec *iov, int iovcnt,
                           off_t offset) {
    return syscall(SYS_pwritev, (long)fd, iov, (long)iovcnt, (long)offset, 0L);
}

static int open_blank_file(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open test file failed");
    return fd;
}

static void test_happy_path(void) {
    const char *path = "/tmp/test_pwritev_happy.bin";
    int fd = open_blank_file(path);

    char a[5] = "ABCDE";
    char b[5] = "FGHIJ";
    struct iovec iov[2] = {
        {.iov_base = a, .iov_len = sizeof(a)},
        {.iov_base = b, .iov_len = sizeof(b)},
    };

    ssize_t n = raw_pwritev(fd, iov, 2, 0);
    EXPECT(n == 10, "pwritev at offset 0 should return 10");

    // pwritev must not advance the file offset.
    off_t pos = lseek(fd, 0, SEEK_CUR);
    EXPECT(pos == 0, "pwritev must not advance the file offset");

    char readback[10];
    memset(readback, 0, sizeof(readback));
    EXPECT(pread(fd, readback, sizeof(readback), 0) == 10, "readback failed");
    EXPECT(memcmp(readback, "ABCDEFGHIJ", 10) == 0,
           "readback content mismatch at offset 0");

    char c[5] = "KLMNO";
    char d[5] = "PQRST";
    struct iovec iov2[2] = {
        {.iov_base = c, .iov_len = sizeof(c)},
        {.iov_base = d, .iov_len = sizeof(d)},
    };
    n = raw_pwritev(fd, iov2, 2, 10);
    EXPECT(n == 10, "pwritev at offset 10 should return 10");

    pos = lseek(fd, 0, SEEK_CUR);
    EXPECT(pos == 0, "pwritev must still not advance the offset");

    char full[20];
    memset(full, 0, sizeof(full));
    EXPECT(pread(fd, full, sizeof(full), 0) == 20, "full readback failed");
    EXPECT(memcmp(full, "ABCDEFGHIJKLMNOPQRST", 20) == 0,
           "full content mismatch after second pwritev");

    close(fd);
    unlink(path);
}

static void test_extends_file(void) {
    const char *path = "/tmp/test_pwritev_extend.bin";
    int fd = open_blank_file(path);

    char buf[4] = "WXYZ";
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};

    ssize_t n = raw_pwritev(fd, iov, 1, 100);
    EXPECT(n == 4, "pwritev past EOF should extend the file");

    off_t end = lseek(fd, 0, SEEK_END);
    EXPECT(end == 104, "file size should be offset + bytes written");

    char readback[4];
    EXPECT(pread(fd, readback, sizeof(readback), 100) == 4, "readback failed");
    EXPECT(memcmp(readback, "WXYZ", 4) == 0,
           "extended file content mismatch");

    close(fd);
    unlink(path);
}

static void test_zero_iovcnt(void) {
    const char *path = "/tmp/test_pwritev_zero.bin";
    int fd = open_blank_file(path);

    struct iovec iov[1] = {{.iov_base = NULL, .iov_len = 0}};
    ssize_t n = raw_pwritev(fd, iov, 0, 0);
    EXPECT(n == 0, "pwritev with iovcnt 0 should return 0");

    off_t end = lseek(fd, 0, SEEK_END);
    EXPECT(end == 0, "file should still be empty");

    close(fd);
    unlink(path);
}

static void test_bad_fd(void) {
    char buf[4] = "data";
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};

    errno = 0;
    ssize_t n = raw_pwritev(-1, iov, 1, 0);
    EXPECT(n == -1 && errno == EBADF, "pwritev on fd -1 should fail with EBADF");

    int fd = open("/tmp/test_pwritev_bad.bin", O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open for closed-fd test failed");
    close(fd);
    unlink("/tmp/test_pwritev_bad.bin");

    errno = 0;
    n = raw_pwritev(fd, iov, 1, 0);
    EXPECT(n == -1 && errno == EBADF,
           "pwritev on closed fd should fail with EBADF");
}

static void test_negative_offset(void) {
    const char *path = "/tmp/test_pwritev_negoff.bin";
    int fd = open_blank_file(path);

    char buf[4] = "data";
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};

    errno = 0;
    ssize_t n = raw_pwritev(fd, iov, 1, -1);
    EXPECT(n == -1 && errno == EINVAL,
           "pwritev with negative offset should fail with EINVAL");

    close(fd);
    unlink(path);
}

static void test_pipe_espipe(void) {
    int p[2];
    EXPECT(pipe(p) == 0, "pipe creation failed");

    char buf[4] = "data";
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};
    errno = 0;
    ssize_t n = raw_pwritev(p[1], iov, 1, 0);
    EXPECT(n == -1 && errno == ESPIPE,
           "pwritev on a pipe should fail with ESPIPE");

    close(p[0]);
    close(p[1]);
}

static void test_readonly_fd(void) {
    const char *path = "/tmp/test_pwritev_ro.bin";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open rw for setup failed");
    EXPECT(write(fd, "x", 1) == 1, "setup write failed");
    close(fd);

    fd = open(path, O_RDONLY);
    EXPECT(fd >= 0, "reopen read-only failed");

    char buf[4] = "data";
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};
    errno = 0;
    ssize_t n = raw_pwritev(fd, iov, 1, 0);
    EXPECT(n == -1 && errno == EBADF,
           "pwritev on read-only fd should fail with EBADF");

    close(fd);
    unlink(path);
}

int main(void) {
    printf("===== pwritev tests =====\n");
    test_happy_path();
    test_extends_file();
    test_zero_iovcnt();
    test_bad_fd();
    test_negative_offset();
    test_pipe_espipe();
    test_readonly_fd();
    printf("All pwritev tests passed.\n");
    return 0;
}
