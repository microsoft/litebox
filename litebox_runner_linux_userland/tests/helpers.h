// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Shared helpers for the C tests in this directory. `static inline` so each
// translation unit gets its own copy without a link step; the test runner's
// compile cache tracks sibling `.h` files for invalidation.

#ifndef LITEBOX_TESTS_HELPERS_H
#define LITEBOX_TESTS_HELPERS_H

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

static inline void die(const char *msg) {
    perror(msg);
    exit(1);
}

static inline void fail_errno(const char *op, int expected_errno) {
    fprintf(stderr, "FAIL: %s expected errno=%d (%s), got errno=%d (%s)\n",
            op, expected_errno, strerror(expected_errno), errno, strerror(errno));
    exit(1);
}

static inline void expect_sys_shutdown(int fd, int how, const char *op) {
    errno = 0;
    if (syscall(SYS_shutdown, fd, how) != 0) {
        die(op);
    }
}

static inline void expect_sys_shutdown_errno(int fd, int how, int expected_errno, const char *op) {
    errno = 0;
    long ret = syscall(SYS_shutdown, fd, how);
    if (ret != -1) {
        fprintf(stderr, "FAIL: %s expected failure, got %ld\n", op, ret);
        exit(1);
    }
    if (errno != expected_errno) {
        fail_errno(op, expected_errno);
    }
}

static inline void expect_send_errno(int fd, int expected_errno, const char *op) {
    errno = 0;
    ssize_t n = send(fd, "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n != -1) {
        fprintf(stderr, "FAIL: %s expected failure, got %zd\n", op, n);
        exit(1);
    }
    if (errno != expected_errno) {
        fail_errno(op, expected_errno);
    }
}

// Blocking recv (no MSG_DONTWAIT) that we expect to time out via SO_RCVTIMEO. Distinct from
// expect_recv_errno because we want to observe that the kernel kept blocking until the
// timer expired, not that it gave up immediately with the same errno.
static inline void expect_blocking_recv_eagain(int fd, const char *op) {
    char buf[32];

    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n != -1) {
        fprintf(stderr, "FAIL: %s expected timeout failure, got %zd\n", op, n);
        exit(1);
    }
    if (errno != EAGAIN) {
        fail_errno(op, EAGAIN);
    }
}

static inline void expect_recv_errno(int fd, int expected_errno, const char *op) {
    char buf[32];

    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n != -1) {
        fprintf(stderr, "FAIL: %s expected failure, got %zd\n", op, n);
        exit(1);
    }
    if (errno != expected_errno) {
        fail_errno(op, expected_errno);
    }
}

static inline void expect_recv_eof(int fd, const char *op) {
    char buf[32];

    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
        die(op);
    }
    if (n != 0) {
        fprintf(stderr, "FAIL: %s expected EOF, got %zd\n", op, n);
        exit(1);
    }
}

static inline void expect_recv_string(int fd, const char *expected, const char *op) {
    char buf[64];
    size_t expected_len = strlen(expected);

    memset(buf, 0, sizeof(buf));
    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n < 0) {
        die(op);
    }
    if ((size_t)n != expected_len || memcmp(buf, expected, expected_len) != 0) {
        fprintf(stderr, "FAIL: %s expected '%s' (%zu bytes), got '%.*s' (%zd bytes)\n",
                op, expected, expected_len, (int)n, buf, n);
        exit(1);
    }
}

static inline void make_socket_pair(int type, int sv[2]) {
    if (socketpair(AF_UNIX, type, 0, sv) != 0) {
        die("socketpair(AF_UNIX)");
    }
}

static inline void set_recv_timeout(int fd) {
    struct timeval timeout = { .tv_sec = 0, .tv_usec = 100000 };

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        die("setsockopt(SO_RCVTIMEO)");
    }
}

static inline void close_pair(int sv[2]) {
    close(sv[0]);
    close(sv[1]);
}

// Single-shot poll(2) for level-triggered checks. Asserts `r=1` (revents
// present) and that the bits in `expected_set` are all set; ignores any
// additional bits the kernel reports.
static inline void expect_poll_has(int fd, short events_mask, short expected_set, const char *op) {
    struct pollfd pfd = { .fd = fd, .events = events_mask };
    errno = 0;
    int r = poll(&pfd, 1, 0);
    if (r < 0) {
        die(op);
    }
    if (r != 1 || (pfd.revents & expected_set) != expected_set) {
        fprintf(stderr,
                "FAIL: %s expected revents to include 0x%04x, got r=%d revents=0x%04x\n",
                op, (unsigned)expected_set, r, (unsigned)pfd.revents);
        exit(1);
    }
}

// Assert the given bits are NOT set in the poll revents.
static inline void expect_poll_lacks(int fd, short events_mask, short forbidden, const char *op) {
    struct pollfd pfd = { .fd = fd, .events = events_mask };
    errno = 0;
    int r = poll(&pfd, 1, 0);
    if (r < 0) {
        die(op);
    }
    if (pfd.revents & forbidden) {
        fprintf(stderr,
                "FAIL: %s expected revents to exclude 0x%04x, got revents=0x%04x\n",
                op, (unsigned)forbidden, (unsigned)pfd.revents);
        exit(1);
    }
}

#endif // LITEBOX_TESTS_HELPERS_H
