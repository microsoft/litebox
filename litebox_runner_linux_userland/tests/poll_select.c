// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: poll, ppoll, select, pselect
// I/O multiplexing - critical for event-driven applications

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <poll.h>
#include <errno.h>
#include <time.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_poll_pipe_ready(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    // Write to pipe to make it readable
    write(pipefd[1], "x", 1);

    struct pollfd fds[1];
    fds[0].fd = pipefd[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    int ret = poll(fds, 1, 100);  // 100ms timeout
    TEST_ASSERT(ret == 1, "poll should return 1 ready fd");
    TEST_ASSERT(fds[0].revents & POLLIN, "POLLIN should be set");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("poll pipe ready: PASS\n");
    return 0;
}

int test_poll_timeout(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    struct pollfd fds[1];
    fds[0].fd = pipefd[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int ret = poll(fds, 1, 50);  // 50ms timeout

    clock_gettime(CLOCK_MONOTONIC, &end);

    TEST_ASSERT(ret == 0, "poll should timeout with 0");

    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                      (end.tv_nsec - start.tv_nsec) / 1000000;
    TEST_ASSERT(elapsed_ms >= 40, "should wait at least ~50ms");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("poll timeout: PASS\n");
    return 0;
}

int test_poll_write_ready(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    struct pollfd fds[1];
    fds[0].fd = pipefd[1];  // write end
    fds[0].events = POLLOUT;
    fds[0].revents = 0;

    int ret = poll(fds, 1, 0);  // immediate
    TEST_ASSERT(ret == 1, "poll should show write ready");
    TEST_ASSERT(fds[0].revents & POLLOUT, "POLLOUT should be set");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("poll write ready: PASS\n");
    return 0;
}

int test_poll_hup(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    // Close write end
    close(pipefd[1]);

    struct pollfd fds[1];
    fds[0].fd = pipefd[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    int ret = poll(fds, 1, 0);
    TEST_ASSERT(ret == 1, "poll should return for HUP");
    TEST_ASSERT(fds[0].revents & POLLHUP, "POLLHUP should be set");

    close(pipefd[0]);
    printf("poll HUP: PASS\n");
    return 0;
}

int test_select_read_ready(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    // Write to pipe
    write(pipefd[1], "test", 4);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(pipefd[0], &readfds);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  // 100ms

    int ret = select(pipefd[0] + 1, &readfds, NULL, NULL, &tv);
    TEST_ASSERT(ret == 1, "select should return 1");
    TEST_ASSERT(FD_ISSET(pipefd[0], &readfds), "read fd should be set");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("select read ready: PASS\n");
    return 0;
}

int test_select_timeout(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(pipefd[0], &readfds);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };  // 50ms

    int ret = select(pipefd[0] + 1, &readfds, NULL, NULL, &tv);
    TEST_ASSERT(ret == 0, "select should timeout");
    TEST_ASSERT(!FD_ISSET(pipefd[0], &readfds), "fd should not be set on timeout");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("select timeout: PASS\n");
    return 0;
}

int test_select_write_ready(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(pipefd[1], &writefds);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };  // immediate

    int ret = select(pipefd[1] + 1, NULL, &writefds, NULL, &tv);
    TEST_ASSERT(ret == 1, "select should show write ready");
    TEST_ASSERT(FD_ISSET(pipefd[1], &writefds), "write fd should be set");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("select write ready: PASS\n");
    return 0;
}

int test_poll_invalid_fd(void) {
    struct pollfd fds[1];
    fds[0].fd = -1;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    int ret = poll(fds, 1, 0);
    // poll with invalid fd should return 0 or set POLLNVAL
    TEST_ASSERT(ret >= 0, "poll should not fail with invalid fd");
    if (ret == 1) {
        TEST_ASSERT(fds[0].revents & POLLNVAL, "POLLNVAL should be set for invalid fd");
    }

    printf("poll invalid fd: PASS\n");
    return 0;
}

int test_poll_multiple_fds(void) {
    int pipe1[2], pipe2[2];
    TEST_ASSERT(pipe(pipe1) == 0, "pipe1 failed");
    TEST_ASSERT(pipe(pipe2) == 0, "pipe2 failed");

    // Write to first pipe only
    write(pipe1[1], "x", 1);

    struct pollfd fds[2];
    fds[0].fd = pipe1[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = pipe2[0];
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    int ret = poll(fds, 2, 50);
    TEST_ASSERT(ret == 1, "poll should return 1 ready fd");
    TEST_ASSERT(fds[0].revents & POLLIN, "first pipe should be ready");
    TEST_ASSERT(!(fds[1].revents & POLLIN), "second pipe should not be ready");

    close(pipe1[0]); close(pipe1[1]);
    close(pipe2[0]); close(pipe2[1]);
    printf("poll multiple fds: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting poll/select tests...\n");

    if (test_poll_pipe_ready() != 0) return 1;
    if (test_poll_timeout() != 0) return 1;
    if (test_poll_write_ready() != 0) return 1;
    if (test_poll_hup() != 0) return 1;
    if (test_poll_invalid_fd() != 0) return 1;
    if (test_poll_multiple_fds() != 0) return 1;
    if (test_select_read_ready() != 0) return 1;
    if (test_select_timeout() != 0) return 1;
    if (test_select_write_ready() != 0) return 1;

    printf("All poll/select tests passed!\n");
    return 0;
}
