// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static int g_fail = 0;

static void check(int cond, const char *what) {
    if (cond) {
        printf("  PASS: %s\n", what);
    } else {
        printf("  FAIL: %s\n", what);
        g_fail = 1;
    }
}

// Use the raw syscall so we exercise exactly what LiteBox intercepts; glibc's
// wrapper would otherwise be free to massage arguments before reaching the
// kernel. The libc prototype takes a non-const timespec, so do likewise.
static long sys_recvmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen,
                         int flags, struct timespec *timeout) {
    return syscall(SYS_recvmmsg, fd, msgvec, vlen, flags, timeout);
}

// Helper: build a vlen-sized array of mmsghdrs, each with one iov pointing at
// the corresponding row of `bufs`. msg_len is poisoned so we can prove the
// kernel wrote it.
static void build_recv_hdrs(struct mmsghdr *hdrs, struct iovec *iov,
                            char (*bufs)[64], unsigned int vlen) {
    memset(hdrs, 0xAB, sizeof(*hdrs) * vlen);
    for (unsigned int i = 0; i < vlen; i++) {
        memset(bufs[i], 0, 64);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = 63; // leave room for a NUL
        memset(&hdrs[i].msg_hdr, 0, sizeof(hdrs[i].msg_hdr));
        hdrs[i].msg_hdr.msg_iov = &iov[i];
        hdrs[i].msg_hdr.msg_iovlen = 1;
        hdrs[i].msg_len = 0xDEADBEEF;
    }
}

// ---------------------------------------------------------------------------
// Test 1: pre-buffer three datagrams and drain them in one recvmmsg call.
// Default flags=0 still works here because the data is already queued, so the
// "block until vlen messages" semantics never have to actually wait.
// ---------------------------------------------------------------------------
static void test_three_messages(void) {
    puts("Test 1: recvmmsg drains multiple queued datagrams in one call");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    const char *payloads[3] = {"hello", "world!!", "third-msg"};
    for (int i = 0; i < 3; i++) {
        ssize_t n = send(sv[0], payloads[i], strlen(payloads[i]), 0);
        if (n != (ssize_t)strlen(payloads[i])) {
            perror("send");
            exit(2);
        }
    }

    struct iovec iov[3];
    struct mmsghdr hdrs[3];
    char bufs[3][64];
    build_recv_hdrs(hdrs, iov, bufs, 3);

    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 3, 0, NULL);
    printf("  recvmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == 3, "recvmmsg returned 3 (number of messages received)");

    for (int i = 0; i < 3; i++) {
        unsigned int got = hdrs[i].msg_len;
        unsigned int want = (unsigned int)strlen(payloads[i]);
        if (got != want) {
            printf("    msg_len[%d] = %u, want %u\n", i, got, want);
        }
        check(got == want, "msg_len matches payload length for each entry");
        check(strcmp(bufs[i], payloads[i]) == 0,
              "iov buffer holds the expected datagram payload");
    }

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 2: vlen == 0 returns 0 immediately, no errno, no work done.
// ---------------------------------------------------------------------------
static void test_vlen_zero(void) {
    puts("Test 2: recvmmsg with vlen == 0 returns 0");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    errno = 0;
    long n = sys_recvmmsg(sv[1], NULL, 0, 0, NULL);
    printf("  recvmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == 0, "vlen=0 returns 0");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 3: errno mapping for bad fd / bad msgvec pointer (when no message has
// been received yet).
// ---------------------------------------------------------------------------
static void test_errno_paths(void) {
    puts("Test 3: recvmmsg errno on bad fd / bad msgvec pointer");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    errno = 0;
    long n = sys_recvmmsg(-1, NULL, 1, 0, NULL);
    printf("  fd=-1 vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EBADF, "bad fd returns EBADF");

    errno = 0;
    n = sys_recvmmsg(9999, NULL, 1, 0, NULL);
    printf("  fd=9999 vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EBADF, "unused fd returns EBADF");

    errno = 0;
    n = sys_recvmmsg(sv[1], NULL, 1, MSG_DONTWAIT, NULL);
    printf("  fd=ok msgvec=NULL vlen=1 DONTWAIT: ret=%ld errno=%d (%s)\n", n,
           errno, n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EFAULT, "NULL msgvec with vlen>0 returns EFAULT");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 4: MSG_DONTWAIT on an empty socket returns -1 / EAGAIN.
// ---------------------------------------------------------------------------
static void test_dontwait_empty(void) {
    puts("Test 4: MSG_DONTWAIT on empty queue returns EAGAIN");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    struct iovec iov[2];
    struct mmsghdr hdrs[2];
    char bufs[2][64];
    build_recv_hdrs(hdrs, iov, bufs, 2);

    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 2, MSG_DONTWAIT, NULL);
    printf("  recvmmsg DONTWAIT empty: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "empty queue with DONTWAIT returns EAGAIN/EWOULDBLOCK");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 5: MSG_DONTWAIT — partial drain. Pre-buffer two datagrams, ask for
// five; we should get two back and msg_len for those two should be set.
// ---------------------------------------------------------------------------
static void test_dontwait_partial(void) {
    puts("Test 5: MSG_DONTWAIT returns however many are queued (partial)");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    const char *payloads[2] = {"alpha", "beta!!"};
    for (int i = 0; i < 2; i++) {
        ssize_t n = send(sv[0], payloads[i], strlen(payloads[i]), 0);
        if (n != (ssize_t)strlen(payloads[i])) {
            perror("send");
            exit(2);
        }
    }

    struct iovec iov[5];
    struct mmsghdr hdrs[5];
    char bufs[5][64];
    build_recv_hdrs(hdrs, iov, bufs, 5);

    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 5, MSG_DONTWAIT, NULL);
    printf("  recvmmsg DONTWAIT vlen=5 queued=2: ret=%ld errno=%d (%s)\n", n,
           errno, n < 0 ? strerror(errno) : "-");
    check(n == 2, "returns 2 (number queued)");
    for (int i = 0; i < 2; i++) {
        unsigned int got = hdrs[i].msg_len;
        unsigned int want = (unsigned int)strlen(payloads[i]);
        if (got != want) {
            printf("    msg_len[%d] = %u, want %u\n", i, got, want);
        }
        check(got == want, "msg_len matches payload length");
        check(strcmp(bufs[i], payloads[i]) == 0, "payload arrived in iov");
    }

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test: tv_nsec/tv_sec validation. Linux validates the timespec before the
// fd/msgvec — `poll_select_set_timeout` runs first in `do_recvmmsg`.
// ---------------------------------------------------------------------------
static void test_bad_timespec(void) {
    puts("Test: invalid timespec returns EINVAL (before EBADF/EFAULT)");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    struct iovec iov[1];
    struct mmsghdr hdrs[1];
    char bufs[1][64];
    build_recv_hdrs(hdrs, iov, bufs, 1);

    // tv_sec < 0
    struct timespec ts_neg_sec = {-1, 0};
    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 1, MSG_DONTWAIT, &ts_neg_sec);
    printf("  tv_sec=-1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EINVAL, "negative tv_sec returns EINVAL");

    // tv_nsec >= 1_000_000_000
    struct timespec ts_big_nsec = {0, 1000000000};
    errno = 0;
    n = sys_recvmmsg(sv[1], hdrs, 1, MSG_DONTWAIT, &ts_big_nsec);
    printf("  tv_nsec=1e9: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EINVAL, "tv_nsec >= 1e9 returns EINVAL");

    // Validation precedes EBADF
    errno = 0;
    n = sys_recvmmsg(-1, hdrs, 1, MSG_DONTWAIT, &ts_neg_sec);
    printf("  fd=-1 + tv_sec=-1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EINVAL,
          "timespec validation runs before fd check");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test: non-NULL timeout on an empty queue with MSG_DONTWAIT still returns
// EAGAIN (DONTWAIT short-circuits the inner recvmsg before the deadline ever
// matters).
// ---------------------------------------------------------------------------
static void test_timeout_dontwait_empty(void) {
    puts("Test: timeout + DONTWAIT on empty queue returns EAGAIN");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    struct iovec iov[2];
    struct mmsghdr hdrs[2];
    char bufs[2][64];
    build_recv_hdrs(hdrs, iov, bufs, 2);

    struct timespec ts = {0, 10000000}; // 10ms
    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 2, MSG_DONTWAIT, &ts);
    printf("  recvmmsg DONTWAIT timeout=10ms empty: ret=%ld errno=%d (%s)\n", n,
           errno, n < 0 ? strerror(errno) : "-");
    check(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "DONTWAIT on empty with timeout returns EAGAIN");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test: zero timespec ({0,0}) on a queued socket reads exactly ONE message
// before the deadline check fires. `poll_select_set_timeout` parks the
// deadline at {0,0}, which compares as already past after the first recvmsg
// returns, so the loop exits with datagrams=1.
// ---------------------------------------------------------------------------
static void test_timeout_zero_caps_at_one(void) {
    puts("Test: timeout={0,0} reads exactly 1 message even with vlen > 1");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    const char *payloads[3] = {"first", "second", "third!"};
    for (int i = 0; i < 3; i++) {
        ssize_t sent = send(sv[0], payloads[i], strlen(payloads[i]), 0);
        if (sent != (ssize_t)strlen(payloads[i])) {
            perror("send");
            exit(2);
        }
    }

    struct iovec iov[3];
    struct mmsghdr hdrs[3];
    char bufs[3][64];
    build_recv_hdrs(hdrs, iov, bufs, 3);

    struct timespec ts = {0, 0};
    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 3, 0, &ts);
    printf("  recvmmsg ts={0,0} queued=3 vlen=3: ret=%ld errno=%d (%s)\n", n,
           errno, n < 0 ? strerror(errno) : "-");
    check(n == 1, "timeout={0,0} returns 1");
    check(hdrs[0].msg_len == strlen(payloads[0]),
          "msg_len[0] matches first payload length");
    check(strcmp(bufs[0], payloads[0]) == 0,
          "iov[0] holds the first payload");
    // msg_len[1] was poisoned to 0xDEADBEEF and shouldn't have been written.
    check(hdrs[1].msg_len == 0xDEADBEEF, "msg_len[1] left untouched");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test: a generous timeout doesn't truncate a multi-message drain. With a 5s
// deadline and three queued datagrams, all three are read before the deadline
// is even close.
// ---------------------------------------------------------------------------
static void test_timeout_generous_drains_all(void) {
    puts("Test: generous timeout drains all queued messages");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    const char *payloads[3] = {"aaa", "bbbb", "ccccc"};
    for (int i = 0; i < 3; i++) {
        ssize_t sent = send(sv[0], payloads[i], strlen(payloads[i]), 0);
        if (sent != (ssize_t)strlen(payloads[i])) {
            perror("send");
            exit(2);
        }
    }

    struct iovec iov[5];
    struct mmsghdr hdrs[5];
    char bufs[5][64];
    build_recv_hdrs(hdrs, iov, bufs, 5);

    struct timespec ts = {5, 0};
    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 5, MSG_DONTWAIT, &ts);
    printf("  recvmmsg DONTWAIT ts=5s queued=3 vlen=5: ret=%ld errno=%d (%s)\n",
           n, errno, n < 0 ? strerror(errno) : "-");
    check(n == 3, "drained all 3 queued messages");
    for (int i = 0; i < 3; i++) {
        check(hdrs[i].msg_len == strlen(payloads[i]),
              "msg_len matches payload length");
        check(strcmp(bufs[i], payloads[i]) == 0, "payload arrived in iov");
    }
    // Linux writes the remaining time back into the user's timespec on
    // success (see `put_timespec64` in `__sys_recvmmsg`). Native probe with
    // queued(3)/vlen=5 reports e.g. {4, 999997470}: drain takes microseconds
    // so the residual is just-under 5s, but the kernel did update it.
    printf("  remaining timespec: {%ld, %ld}\n", (long)ts.tv_sec, (long)ts.tv_nsec);
    check(ts.tv_sec < 5, "remaining tv_sec decremented below original 5");
    check(ts.tv_sec >= 0, "remaining tv_sec did not go negative");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 6: MSG_WAITFORONE — pre-buffer two datagrams, ask for five with
// MSG_WAITFORONE. We should get exactly two (the first read blocks, but data
// is already there; subsequent reads are non-blocking).
// ---------------------------------------------------------------------------
static void test_waitforone(void) {
    puts("Test 6: MSG_WAITFORONE drains pre-buffered datagrams");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    const char *payloads[2] = {"one", "two-two"};
    for (int i = 0; i < 2; i++) {
        ssize_t n = send(sv[0], payloads[i], strlen(payloads[i]), 0);
        if (n != (ssize_t)strlen(payloads[i])) {
            perror("send");
            exit(2);
        }
    }

    struct iovec iov[5];
    struct mmsghdr hdrs[5];
    char bufs[5][64];
    build_recv_hdrs(hdrs, iov, bufs, 5);

    errno = 0;
    long n = sys_recvmmsg(sv[1], hdrs, 5, MSG_WAITFORONE, NULL);
    printf("  recvmmsg WAITFORONE vlen=5 queued=2: ret=%ld errno=%d (%s)\n", n,
           errno, n < 0 ? strerror(errno) : "-");
    check(n == 2, "returns 2 (drains all queued after first)");
    for (int i = 0; i < 2; i++) {
        unsigned int got = hdrs[i].msg_len;
        unsigned int want = (unsigned int)strlen(payloads[i]);
        check(got == want, "msg_len matches payload length");
        check(strcmp(bufs[i], payloads[i]) == 0, "payload arrived in iov");
    }

    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    puts("recvmmsg parity test");
    test_three_messages();
    test_vlen_zero();
    test_errno_paths();
    test_dontwait_empty();
    test_dontwait_partial();
    test_waitforone();
    test_bad_timespec();
    test_timeout_dontwait_empty();
    test_timeout_zero_caps_at_one();
    test_timeout_generous_drains_all();

    if (g_fail) {
        puts("\nRESULT: BUG(S) REPRODUCED");
        return 1;
    }
    puts("\nAll recvmmsg tests passed.");
    return 0;
}
