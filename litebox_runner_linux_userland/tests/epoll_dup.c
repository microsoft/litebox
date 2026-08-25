// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: an epoll interest survives closing the registered fd as long as a
// duplicate referring to the same open file description remains open, matching
// Linux epoll(7) semantics ("a file descriptor is removed from an interest
// list only after all the file descriptors referring to the underlying open
// file description have been closed").

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg)                                                \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d: %s)\n",        \
                    __func__, __LINE__, msg, errno, strerror(errno));         \
            return 1;                                                         \
        }                                                                     \
    } while (0)

int main(void) {
    int efd = eventfd(0, EFD_CLOEXEC);
    TEST_ASSERT(efd >= 0, "eventfd failed");

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST_ASSERT(epfd >= 0, "epoll_create1 failed");

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u64 = 0x42;
    TEST_ASSERT(epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) == 0,
                "epoll_ctl ADD failed");

    // The duplicate shares the same open file description as efd.
    int dupfd = dup(efd);
    TEST_ASSERT(dupfd >= 0, "dup failed");

    // Close the originally-registered fd. The interest must survive because
    // dupfd still refers to the same open file description.
    TEST_ASSERT(close(efd) == 0, "close original failed");

    // Make the description readable through the surviving duplicate.
    uint64_t one = 1;
    TEST_ASSERT(write(dupfd, &one, sizeof(one)) == (ssize_t)sizeof(one),
                "write via dup failed");

    // The registration must still be reported, carrying its original data.
    struct epoll_event out[4];
    memset(out, 0, sizeof(out));
    int n = epoll_wait(epfd, out, 4, 1000);
    TEST_ASSERT(n == 1, "epoll_wait should report the surviving registration");
    TEST_ASSERT((out[0].events & EPOLLIN) != 0, "expected EPOLLIN");
    TEST_ASSERT(out[0].data.u64 == 0x42, "event data mismatch");

    // The registration is durable: after draining and re-arming through the
    // duplicate, a second wait still reports it.
    uint64_t val = 0;
    TEST_ASSERT(read(dupfd, &val, sizeof(val)) == (ssize_t)sizeof(val),
                "read via dup failed");
    TEST_ASSERT(val == 1, "unexpected eventfd value");
    TEST_ASSERT(write(dupfd, &one, sizeof(one)) == (ssize_t)sizeof(one),
                "second write via dup failed");
    memset(out, 0, sizeof(out));
    n = epoll_wait(epfd, out, 4, 1000);
    TEST_ASSERT(n == 1, "epoll_wait should still report after re-arm");
    TEST_ASSERT(out[0].data.u64 == 0x42, "event data mismatch after re-arm");

    TEST_ASSERT(close(dupfd) == 0, "close dup failed");
    TEST_ASSERT(close(epfd) == 0, "close epoll failed");

    printf("epoll dup-survival: PASS\n");
    return 0;
}
