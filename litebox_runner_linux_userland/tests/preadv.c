// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: preadv positional vectored read.

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

// The kernel's preadv syscall takes (fd, vec, vlen, pos_l, pos_h). On 64-bit
// platforms pos_h is unused and must be 0.
static ssize_t raw_preadv(int fd, const struct iovec *iov, int iovcnt,
                          off_t offset) {
    return syscall(SYS_preadv, (long)fd, iov, (long)iovcnt, (long)offset, 0L);
}

static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const size_t kAlphabetLen = sizeof(kAlphabet) - 1;

static int open_alphabet_file(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open test file failed");
    EXPECT(write(fd, kAlphabet, kAlphabetLen) == (ssize_t)kAlphabetLen,
           "seed write failed");
    EXPECT(lseek(fd, 0, SEEK_SET) == 0, "rewind seed failed");
    return fd;
}

static void test_happy_path(void) {
    const char *path = "/tmp/test_preadv_happy.bin";
    int fd = open_alphabet_file(path);

    char buf1[5];
    char buf2[5];
    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    struct iovec iov[2] = {
        {.iov_base = buf1, .iov_len = sizeof(buf1)},
        {.iov_base = buf2, .iov_len = sizeof(buf2)},
    };

    ssize_t n = raw_preadv(fd, iov, 2, 0);
    EXPECT(n == 10, "preadv at offset 0 should return 10");
    EXPECT(memcmp(buf1, "ABCDE", 5) == 0, "first iov mismatch at offset 0");
    EXPECT(memcmp(buf2, "FGHIJ", 5) == 0, "second iov mismatch at offset 0");

    // File position must be unchanged by preadv.
    off_t pos = lseek(fd, 0, SEEK_CUR);
    EXPECT(pos == 0, "preadv must not advance the file offset");

    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    n = raw_preadv(fd, iov, 2, 10);
    EXPECT(n == 10, "preadv at offset 10 should return 10");
    EXPECT(memcmp(buf1, "KLMNO", 5) == 0, "first iov mismatch at offset 10");
    EXPECT(memcmp(buf2, "PQRST", 5) == 0, "second iov mismatch at offset 10");

    pos = lseek(fd, 0, SEEK_CUR);
    EXPECT(pos == 0, "preadv must still not advance the offset");

    close(fd);
    unlink(path);
}

static void test_short_read_at_eof(void) {
    const char *path = "/tmp/test_preadv_eof.bin";
    int fd = open_alphabet_file(path);

    char buf1[10];
    char buf2[10];
    memset(buf1, 0xff, sizeof(buf1));
    memset(buf2, 0xff, sizeof(buf2));
    struct iovec iov[2] = {
        {.iov_base = buf1, .iov_len = sizeof(buf1)},
        {.iov_base = buf2, .iov_len = sizeof(buf2)},
    };

    // Only 6 bytes left starting at offset 20.
    ssize_t n = raw_preadv(fd, iov, 2, 20);
    EXPECT(n == 6, "preadv near EOF should return only the remaining bytes");
    EXPECT(memcmp(buf1, "UVWXYZ", 6) == 0, "EOF short-read content mismatch");

    // At EOF returns 0.
    n = raw_preadv(fd, iov, 2, (off_t)kAlphabetLen);
    EXPECT(n == 0, "preadv at EOF should return 0");

    // Past EOF returns 0.
    n = raw_preadv(fd, iov, 2, (off_t)kAlphabetLen + 100);
    EXPECT(n == 0, "preadv past EOF should return 0");

    close(fd);
    unlink(path);
}

static void test_zero_iovcnt(void) {
    const char *path = "/tmp/test_preadv_zero.bin";
    int fd = open_alphabet_file(path);

    struct iovec iov[1] = {{.iov_base = NULL, .iov_len = 0}};
    ssize_t n = raw_preadv(fd, iov, 0, 0);
    EXPECT(n == 0, "preadv with iovcnt 0 should return 0");

    close(fd);
    unlink(path);
}

static void test_bad_fd(void) {
    char buf[4];
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};

    errno = 0;
    ssize_t n = raw_preadv(-1, iov, 1, 0);
    EXPECT(n == -1 && errno == EBADF, "preadv on fd -1 should fail with EBADF");

    // Open then close to get a known-invalid fd value.
    int fd = open("/tmp/test_preadv_bad.bin", O_RDWR | O_CREAT | O_TRUNC, 0600);
    EXPECT(fd >= 0, "open for closed-fd test failed");
    close(fd);
    unlink("/tmp/test_preadv_bad.bin");

    errno = 0;
    n = raw_preadv(fd, iov, 1, 0);
    EXPECT(n == -1 && errno == EBADF,
           "preadv on closed fd should fail with EBADF");
}

static void test_negative_offset(void) {
    const char *path = "/tmp/test_preadv_negoff.bin";
    int fd = open_alphabet_file(path);

    char buf[4];
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};

    errno = 0;
    ssize_t n = raw_preadv(fd, iov, 1, -1);
    EXPECT(n == -1 && errno == EINVAL,
           "preadv with negative offset should fail with EINVAL");

    close(fd);
    unlink(path);
}

static void test_pipe_espipe(void) {
    int p[2];
    EXPECT(pipe(p) == 0, "pipe creation failed");

    char buf[4];
    struct iovec iov[1] = {{.iov_base = buf, .iov_len = sizeof(buf)}};
    errno = 0;
    ssize_t n = raw_preadv(p[0], iov, 1, 0);
    EXPECT(n == -1 && errno == ESPIPE,
           "preadv on a pipe should fail with ESPIPE");

    close(p[0]);
    close(p[1]);
}

int main(void) {
    printf("===== preadv tests =====\n");
    test_happy_path();
    test_short_read_at_eof();
    test_zero_iovcnt();
    test_bad_fd();
    test_negative_offset();
    test_pipe_espipe();
    printf("All preadv tests passed.\n");
    return 0;
}
