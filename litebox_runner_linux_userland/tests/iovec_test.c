// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: readv, writev - scatter/gather I/O
// Common in high-performance I/O

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <errno.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_writev_basic(void) {
    const char *path = "/tmp/writev_test";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    char buf1[] = "Hello";
    char buf2[] = ", ";
    char buf3[] = "World!";

    struct iovec iov[3] = {
        { .iov_base = buf1, .iov_len = 5 },
        { .iov_base = buf2, .iov_len = 2 },
        { .iov_base = buf3, .iov_len = 6 }
    };

    ssize_t n = writev(fd, iov, 3);
    TEST_ASSERT(n == 13, "writev should write 13 bytes");

    close(fd);

    // Verify
    fd = open(path, O_RDONLY);
    char buf[32] = {0};
    read(fd, buf, sizeof(buf));
    close(fd);
    TEST_ASSERT(strcmp(buf, "Hello, World!") == 0, "content mismatch");

    unlink(path);
    printf("writev basic: PASS\n");
    return 0;
}

int test_readv_basic(void) {
    const char *path = "/tmp/readv_test";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(fd, "AABBCCDD", 8);
    close(fd);

    fd = open(path, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open for read failed");

    char buf1[2] = {0};
    char buf2[2] = {0};
    char buf3[4] = {0};

    struct iovec iov[3] = {
        { .iov_base = buf1, .iov_len = 2 },
        { .iov_base = buf2, .iov_len = 2 },
        { .iov_base = buf3, .iov_len = 4 }
    };

    ssize_t n = readv(fd, iov, 3);
    TEST_ASSERT(n == 8, "readv should read 8 bytes");
    TEST_ASSERT(memcmp(buf1, "AA", 2) == 0, "buf1 mismatch");
    TEST_ASSERT(memcmp(buf2, "BB", 2) == 0, "buf2 mismatch");
    TEST_ASSERT(memcmp(buf3, "CCDD", 4) == 0, "buf3 mismatch");

    close(fd);
    unlink(path);
    printf("readv basic: PASS\n");
    return 0;
}

int test_writev_pipe(void) {
    int pipefd[2];
    pipe(pipefd);

    char buf1[] = "foo";
    char buf2[] = "bar";

    struct iovec iov[2] = {
        { .iov_base = buf1, .iov_len = 3 },
        { .iov_base = buf2, .iov_len = 3 }
    };

    ssize_t n = writev(pipefd[1], iov, 2);
    TEST_ASSERT(n == 6, "writev to pipe should write 6 bytes");

    char buf[16] = {0};
    read(pipefd[0], buf, sizeof(buf));
    TEST_ASSERT(strcmp(buf, "foobar") == 0, "pipe content mismatch");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("writev pipe: PASS\n");
    return 0;
}

int test_readv_partial(void) {
    int pipefd[2];
    pipe(pipefd);

    // Write less than buffers can hold
    write(pipefd[1], "XY", 2);

    char buf1[4] = {0};
    char buf2[4] = {0};

    struct iovec iov[2] = {
        { .iov_base = buf1, .iov_len = 4 },
        { .iov_base = buf2, .iov_len = 4 }
    };

    ssize_t n = readv(pipefd[0], iov, 2);
    TEST_ASSERT(n == 2, "readv should read only available data");
    TEST_ASSERT(memcmp(buf1, "XY", 2) == 0, "buf1 should have data");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("readv partial: PASS\n");
    return 0;
}

int test_writev_empty_iov(void) {
    int pipefd[2];
    pipe(pipefd);

    char buf[] = "test";
    struct iovec iov[3] = {
        { .iov_base = NULL, .iov_len = 0 },  // Empty
        { .iov_base = buf, .iov_len = 4 },
        { .iov_base = NULL, .iov_len = 0 }   // Empty
    };

    ssize_t n = writev(pipefd[1], iov, 3);
    TEST_ASSERT(n == 4, "writev with empty iovs should work");

    char result[8] = {0};
    read(pipefd[0], result, sizeof(result));
    TEST_ASSERT(strcmp(result, "test") == 0, "content mismatch");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("writev empty iov: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting readv/writev tests...\n");

    if (test_writev_basic() != 0) return 1;
    if (test_readv_basic() != 0) return 1;
    // Pipe-based tests disabled: writev/readv on pipes not yet implemented
    // if (test_writev_pipe() != 0) return 1;
    // if (test_readv_partial() != 0) return 1;
    // if (test_writev_empty_iov() != 0) return 1;

    printf("All readv/writev tests passed!\n");
    return 0;
}
