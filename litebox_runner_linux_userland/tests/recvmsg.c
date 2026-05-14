// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define SEND_LEN 100

static int g_fail = 0;

static void check(int cond, const char *what) {
    if (cond) {
        printf("  PASS: %s\n", what);
    } else {
        printf("  FAIL: %s\n", what);
        g_fail = 1;
    }
}

// Bind a SOCK_DGRAM AF_UNIX socket to an abstract address so the peer has
// a real source address to deliver in msg_name. (LiteBox does not yet
// support unnamed-path autobind via addrlen == sizeof(sun_family).)
static int make_bound_dgram(void) {
    static int counter = 0;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(2);
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    int n = snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1,
                     "litebox-recvmsg-test-%d-%d", getpid(), counter++);
    socklen_t addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
    if (bind(fd, (struct sockaddr *)&sa, addrlen) < 0) {
        perror("bind");
        exit(2);
    }
    return fd;
}

static void send_one(int from, int to, size_t len) {
    struct sockaddr_un to_addr;
    socklen_t to_len = sizeof(to_addr);
    if (getsockname(to, (struct sockaddr *)&to_addr, &to_len) < 0) {
        perror("getsockname");
        exit(2);
    }
    char *buf = calloc(1, len);
    memset(buf, 'A', len);
    ssize_t n = sendto(from, buf, len, 0, (struct sockaddr *)&to_addr, to_len);
    if (n != (ssize_t)len) {
        perror("sendto");
        exit(2);
    }
    free(buf);
}

// ---------------------------------------------------------------------------
// Test 1: truncated datagram must set MSG_TRUNC in msg_flags.
// ---------------------------------------------------------------------------
static void test_trunc_flag(void) {
    puts("Test 1: recvmsg sets MSG_TRUNC on truncated datagram");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    char sbuf[SEND_LEN];
    memset(sbuf, 'A', sizeof(sbuf));
    if (send(sv[0], sbuf, sizeof(sbuf), 0) != (ssize_t)sizeof(sbuf)) {
        perror("send");
        exit(2);
    }

    char rbuf[10];
    char control[64];
    struct iovec iov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    ssize_t n = recvmsg(sv[1], &msg, 0);
    printf("  recvmsg returned %zd, msg_flags = 0x%x, msg_controllen=%zu\n",
           n, msg.msg_flags, msg.msg_controllen);
    check(n == (ssize_t)sizeof(rbuf), "returned copied byte count (10)");
    check((msg.msg_flags & MSG_TRUNC) != 0,
          "MSG_TRUNC set in msg_flags (datagram > iovec capacity)");
    check(msg.msg_controllen == 0,
          "msg_controllen zeroed when no control messages delivered");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 2a: msg_iovlen == 0 must not return EINVAL; must dequeue and set
// MSG_TRUNC.
// ---------------------------------------------------------------------------
static void test_zero_iovlen(void) {
    puts("Test 2a: recvmsg with msg_iovlen == 0 dequeues a datagram");

    int rx = make_bound_dgram();
    int tx = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (tx < 0) { perror("socket"); exit(2); }
    send_one(tx, rx, SEND_LEN);

    struct sockaddr_un name;
    char control[64];
    memset(&name, 0xAB, sizeof(name));
    struct msghdr msg = {0};
    msg.msg_name = &name;
    msg.msg_namelen = sizeof(name);
    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    errno = 0;
    ssize_t n = recvmsg(rx, &msg, 0);
    printf("  recvmsg returned %zd (errno=%d %s), msg_flags=0x%x, "
           "msg_namelen=%u, msg_controllen=%zu\n",
           n, errno, n < 0 ? strerror(errno) : "-", msg.msg_flags,
           (unsigned)msg.msg_namelen, msg.msg_controllen);
    check(n == 0, "returned 0 (not -1/EINVAL)");
    check((msg.msg_flags & MSG_TRUNC) != 0,
          "MSG_TRUNC set (whole datagram discarded)");
    check(msg.msg_controllen == 0,
          "msg_controllen zeroed when no control messages delivered");

    // Datagram should have been consumed: a non-blocking peek must now
    // report no data.
    char tmp[1];
    ssize_t m = recv(rx, tmp, sizeof(tmp), MSG_DONTWAIT);
    check(m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "datagram was actually dequeued");

    close(rx);
    close(tx);
}

// ---------------------------------------------------------------------------
// Test 2b: single iovec with iov_len == 0 must dequeue and set MSG_TRUNC,
// not silently return 0 leaving the datagram queued.
// ---------------------------------------------------------------------------
static void test_zero_capacity_iov(void) {
    puts("Test 2b: recvmsg with single zero-length iovec dequeues a datagram");

    int rx = make_bound_dgram();
    int tx = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (tx < 0) { perror("socket"); exit(2); }
    send_one(tx, rx, SEND_LEN);

    char control[64];
    struct iovec iov = { .iov_base = NULL, .iov_len = 0 };
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    errno = 0;
    ssize_t n = recvmsg(rx, &msg, 0);
    printf("  recvmsg returned %zd (errno=%d %s), msg_flags=0x%x, "
           "msg_controllen=%zu\n",
           n, errno, n < 0 ? strerror(errno) : "-", msg.msg_flags,
           msg.msg_controllen);
    check(n == 0, "returned 0");
    check((msg.msg_flags & MSG_TRUNC) != 0,
          "MSG_TRUNC set (whole datagram discarded)");
    check(msg.msg_controllen == 0,
          "msg_controllen zeroed when no control messages delivered");

    char tmp[1];
    ssize_t m = recv(rx, tmp, sizeof(tmp), MSG_DONTWAIT);
    check(m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "datagram was actually dequeued");

    close(rx);
    close(tx);
}

int main(void) {
    test_trunc_flag();
    test_zero_iovlen();
    test_zero_capacity_iov();

    if (g_fail) {
        puts("\nRESULT: BUG(S) REPRODUCED");
        return 1;
    }
    puts("\nRESULT: OK (Linux behavior)");
    return 0;
}
