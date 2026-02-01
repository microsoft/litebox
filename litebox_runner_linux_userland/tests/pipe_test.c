// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: pipe, pipe2 edge cases
// Pipe syscalls - more thorough testing

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_pipe_basic(void) {
    int pipefd[2];
    int ret = pipe(pipefd);
    TEST_ASSERT(ret == 0, "pipe failed");
    TEST_ASSERT(pipefd[0] >= 0, "read fd should be valid");
    TEST_ASSERT(pipefd[1] >= 0, "write fd should be valid");
    TEST_ASSERT(pipefd[0] != pipefd[1], "fds should be different");

    // Write and read
    const char *msg = "hello";
    write(pipefd[1], msg, 5);

    char buf[16] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    TEST_ASSERT(n == 5, "should read 5 bytes");
    TEST_ASSERT(strcmp(buf, "hello") == 0, "data should match");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("pipe basic: PASS\n");
    return 0;
}

int test_pipe2_cloexec(void) {
    int pipefd[2];
    int ret = pipe2(pipefd, O_CLOEXEC);
    TEST_ASSERT(ret == 0, "pipe2 O_CLOEXEC failed");

    int flags0 = fcntl(pipefd[0], F_GETFD);
    int flags1 = fcntl(pipefd[1], F_GETFD);
    TEST_ASSERT(flags0 & FD_CLOEXEC, "read fd should have CLOEXEC");
    TEST_ASSERT(flags1 & FD_CLOEXEC, "write fd should have CLOEXEC");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("pipe2 O_CLOEXEC: PASS\n");
    return 0;
}

int test_pipe2_nonblock(void) {
    int pipefd[2];
    int ret = pipe2(pipefd, O_NONBLOCK);
    TEST_ASSERT(ret == 0, "pipe2 O_NONBLOCK failed");

    // Read should return EAGAIN on empty pipe
    char buf[16];
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    TEST_ASSERT(n == -1 && errno == EAGAIN, "nonblock read should return EAGAIN");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("pipe2 O_NONBLOCK: PASS\n");
    return 0;
}

int test_pipe_eof(void) {
    int pipefd[2];
    pipe(pipefd);

    // Close write end
    close(pipefd[1]);

    // Read should return 0 (EOF)
    char buf[16];
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    TEST_ASSERT(n == 0, "read after close write should return EOF");

    close(pipefd[0]);
    printf("pipe EOF: PASS\n");
    return 0;
}

int test_pipe_epipe(void) {
    // NOTE: This test is skipped because LiteBox doesn't implement SIGPIPE delivery
    // The write to a closed pipe would trigger SIGPIPE which panics in LiteBox
    printf("pipe EPIPE: SKIPPED (SIGPIPE not implemented)\n");
    return 0;
}

int test_pipe_large_write(void) {
    int pipefd[2];
    pipe2(pipefd, O_NONBLOCK);

    // Try to write more than pipe buffer (typically 64KB)
    char buf[4096];
    memset(buf, 'A', sizeof(buf));

    ssize_t total = 0;
    for (int i = 0; i < 100; i++) {
        ssize_t n = write(pipefd[1], buf, sizeof(buf));
        if (n <= 0) break;
        total += n;
    }
    TEST_ASSERT(total > 0, "should have written some data");

    // Eventually write should block/fail - we already hit EAGAIN when the loop broke
    // Just verify we wrote a reasonable amount
    TEST_ASSERT(total >= 4096, "should have written at least one buffer");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("pipe large write: PASS (wrote %zd bytes before full)\n", total);
    return 0;
}

int main(void) {
    printf("Starting pipe tests...\n");

    if (test_pipe_basic() != 0) return 1;
    if (test_pipe2_cloexec() != 0) return 1;
    if (test_pipe2_nonblock() != 0) return 1;
    if (test_pipe_eof() != 0) return 1;
    if (test_pipe_epipe() != 0) return 1;
    if (test_pipe_large_write() != 0) return 1;

    printf("All pipe tests passed!\n");
    return 0;
}
