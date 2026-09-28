// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: an epoll interest survives closing the registered fd as long as a
// duplicate referring to the same open file description remains open, and is
// gone once every such descriptor is closed (epoll(7)).

#include "helpers.h"

#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#define DATA 0x42

static void add_interest(int epfd, int fd, uint32_t events) {
    struct epoll_event ev = {.events = events, .data.u64 = DATA};
    TEST_ASSERT(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0, "epoll_ctl ADD");
}

// Expects exactly one reported event (containing `events`) if `events` is
// nonzero, and no reported events otherwise.
static void expect_events(int epfd, uint32_t events, int timeout_ms) {
    struct epoll_event out[4];
    memset(out, 0, sizeof(out));
    int n = epoll_wait(epfd, out, 4, timeout_ms);
    if (events == 0) {
        TEST_ASSERT(n == 0, "closed description must not be reported");
        return;
    }
    TEST_ASSERT(n == 1, "surviving registration must be reported");
    TEST_ASSERT((out[0].events & events) == events, "unexpected events");
    TEST_ASSERT(out[0].data.u64 == DATA, "event data mismatch");
}

static void test_eventfd(void) {
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST_ASSERT(epfd >= 0, "epoll_create1");
    int efd = eventfd(0, EFD_CLOEXEC);
    TEST_ASSERT(efd >= 0, "eventfd");
    add_interest(epfd, efd, EPOLLIN);

    int dupfd = dup(efd);
    TEST_ASSERT(dupfd >= 0, "dup");
    TEST_ASSERT(close(efd) == 0, "close original");

    uint64_t one = 1;
    TEST_ASSERT(write(dupfd, &one, sizeof(one)) == sizeof(one), "write via dup");
    expect_events(epfd, EPOLLIN, 1000);

    // The registration is durable across draining and re-arming.
    uint64_t val = 0;
    TEST_ASSERT(read(dupfd, &val, sizeof(val)) == sizeof(val) && val == 1, "read via dup");
    expect_events(epfd, 0, 0);
    TEST_ASSERT(write(dupfd, &one, sizeof(one)) == sizeof(one), "second write via dup");
    expect_events(epfd, EPOLLIN, 1000);

    TEST_ASSERT(close(dupfd) == 0, "close dup");
    expect_events(epfd, 0, 0);
    TEST_ASSERT(close(epfd) == 0, "close epoll");
}

static void test_pipe(void) {
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST_ASSERT(epfd >= 0, "epoll_create1");
    int fds[2];
    TEST_ASSERT(pipe2(fds, O_CLOEXEC) == 0, "pipe2");
    add_interest(epfd, fds[0], EPOLLIN);

    int dupfd = dup(fds[0]);
    TEST_ASSERT(dupfd >= 0, "dup");
    TEST_ASSERT(close(fds[0]) == 0, "close original");

    TEST_ASSERT(write(fds[1], "x", 1) == 1, "write to pipe");
    expect_events(epfd, EPOLLIN, 1000);

    TEST_ASSERT(close(dupfd) == 0, "close dup");
    expect_events(epfd, 0, 0);
    TEST_ASSERT(close(fds[1]) == 0, "close write end");
    TEST_ASSERT(close(epfd) == 0, "close epoll");
}

static void test_udp_socket(void) {
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST_ASSERT(epfd >= 0, "epoll_create1");
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    TEST_ASSERT(sock >= 0, "socket");
    add_interest(epfd, sock, EPOLLOUT);

    int dupfd = dup(sock);
    TEST_ASSERT(dupfd >= 0, "dup");
    TEST_ASSERT(close(sock) == 0, "close original");
    expect_events(epfd, EPOLLOUT, 1000);

    TEST_ASSERT(close(dupfd) == 0, "close dup");
    expect_events(epfd, 0, 0);
    TEST_ASSERT(close(epfd) == 0, "close epoll");
}

int main(void) {
    test_eventfd();
    test_pipe();
    test_udp_socket();
    printf("epoll dup-survival: PASS\n");
    return 0;
}
