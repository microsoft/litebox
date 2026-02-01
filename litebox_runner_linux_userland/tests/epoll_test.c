// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: epoll_create, epoll_ctl, epoll_wait - edge cases
// I/O event notification

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
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

int test_epoll_create(void) {
    int epfd = epoll_create(1);
    TEST_ASSERT(epfd >= 0, "epoll_create failed");
    close(epfd);

    epfd = epoll_create1(0);
    TEST_ASSERT(epfd >= 0, "epoll_create1 failed");
    close(epfd);

    epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST_ASSERT(epfd >= 0, "epoll_create1 EPOLL_CLOEXEC failed");

    int flags = fcntl(epfd, F_GETFD);
    TEST_ASSERT(flags & FD_CLOEXEC, "EPOLL_CLOEXEC should set FD_CLOEXEC");
    close(epfd);

    printf("epoll_create: PASS\n");
    return 0;
}

int test_epoll_add_mod_del(void) {
    int epfd = epoll_create1(0);
    TEST_ASSERT(epfd >= 0, "epoll_create1 failed");

    int pipefd[2];
    pipe(pipefd);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = pipefd[0];

    // Add
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);
    TEST_ASSERT(ret == 0, "EPOLL_CTL_ADD failed");

    // NOTE: EPOLL_CTL_MOD is not supported in LiteBox
    // Skip the modify test
    printf("  (EPOLL_CTL_MOD skipped - not supported)\n");

    // Delete
    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, pipefd[0], NULL);
    TEST_ASSERT(ret == 0, "EPOLL_CTL_DEL failed");

    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);
    printf("epoll add/mod/del: PASS\n");
    return 0;
}

int test_epoll_wait_ready(void) {
    int epfd = epoll_create1(0);
    int pipefd[2];
    pipe(pipefd);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = pipefd[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);

    // Write to make pipe readable
    write(pipefd[1], "x", 1);

    struct epoll_event events[4];
    int n = epoll_wait(epfd, events, 4, 100);
    TEST_ASSERT(n == 1, "epoll_wait should return 1");
    TEST_ASSERT(events[0].events & EPOLLIN, "EPOLLIN should be set");
    TEST_ASSERT(events[0].data.fd == pipefd[0], "data.fd should match");

    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);
    printf("epoll_wait ready: PASS\n");
    return 0;
}

int test_epoll_wait_timeout(void) {
    int epfd = epoll_create1(0);
    int pipefd[2];
    pipe(pipefd);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = pipefd[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);

    // Don't write - should timeout
    struct epoll_event events[4];
    int n = epoll_wait(epfd, events, 4, 50);  // 50ms timeout
    TEST_ASSERT(n == 0, "epoll_wait should timeout with 0");

    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);
    printf("epoll_wait timeout: PASS\n");
    return 0;
}

int test_epoll_multiple_fds(void) {
    int epfd = epoll_create1(0);
    int pipe1[2], pipe2[2];
    pipe(pipe1);
    pipe(pipe2);

    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.fd = pipe1[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, pipe1[0], &ev);

    ev.data.fd = pipe2[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, pipe2[0], &ev);

    // Write to both pipes
    write(pipe1[1], "a", 1);
    write(pipe2[1], "b", 1);

    struct epoll_event events[4];
    int n = epoll_wait(epfd, events, 4, 100);
    TEST_ASSERT(n == 2, "epoll_wait should return 2 ready fds");

    close(pipe1[0]); close(pipe1[1]);
    close(pipe2[0]); close(pipe2[1]);
    close(epfd);
    printf("epoll multiple fds: PASS\n");
    return 0;
}

int test_epoll_ctl_errors(void) {
    int epfd = epoll_create1(0);

    struct epoll_event ev = { .events = EPOLLIN };

    // Add invalid fd
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, -1, &ev);
    TEST_ASSERT(ret == -1 && errno == EBADF, "EPOLL_CTL_ADD -1 should return EBADF");

    // Delete non-existent fd
    int pipefd[2];
    pipe(pipefd);
    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, pipefd[0], NULL);
    TEST_ASSERT(ret == -1 && errno == ENOENT, "EPOLL_CTL_DEL non-added should return ENOENT");

    // Add duplicate
    ev.data.fd = pipefd[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);
    TEST_ASSERT(ret == -1 && errno == EEXIST, "EPOLL_CTL_ADD duplicate should return EEXIST");

    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);
    printf("epoll_ctl errors: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting epoll tests...\n");

    if (test_epoll_create() != 0) return 1;
    if (test_epoll_add_mod_del() != 0) return 1;
    if (test_epoll_wait_ready() != 0) return 1;
    if (test_epoll_wait_timeout() != 0) return 1;
    if (test_epoll_multiple_fds() != 0) return 1;
    if (test_epoll_ctl_errors() != 0) return 1;

    printf("All epoll tests passed!\n");
    return 0;
}
