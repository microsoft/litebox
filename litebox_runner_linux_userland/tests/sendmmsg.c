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
// kernel.
static long sys_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen,
                         int flags) {
    return syscall(SYS_sendmmsg, fd, msgvec, vlen, flags);
}

// ---------------------------------------------------------------------------
// Test 1: send three datagrams in one sendmmsg, recv them and check msg_len is
// written back for every entry.
// ---------------------------------------------------------------------------
static void test_three_messages(void) {
    puts("Test 1: sendmmsg sends multiple datagrams and reports per-entry msg_len");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    const char *payloads[3] = {"hello", "world!!", "third-msg"};
    struct iovec iov[3];
    struct mmsghdr hdrs[3];
    memset(hdrs, 0xAB, sizeof(hdrs));
    for (int i = 0; i < 3; i++) {
        iov[i].iov_base = (void *)payloads[i];
        iov[i].iov_len = strlen(payloads[i]);
        memset(&hdrs[i].msg_hdr, 0, sizeof(hdrs[i].msg_hdr));
        hdrs[i].msg_hdr.msg_iov = &iov[i];
        hdrs[i].msg_hdr.msg_iovlen = 1;
        hdrs[i].msg_len = 0xDEADBEEF;
    }

    errno = 0;
    long n = sys_sendmmsg(sv[0], hdrs, 3, 0);
    printf("  sendmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == 3, "sendmmsg returned 3 (number of messages sent)");
    for (int i = 0; i < 3; i++) {
        unsigned int got = hdrs[i].msg_len;
        unsigned int want = (unsigned int)strlen(payloads[i]);
        if (got != want) {
            printf("    msg_len[%d] = %u, want %u\n", i, got, want);
        }
        check(got == want, "msg_len matches payload length for each entry");
    }

    // Verify each datagram arrives intact and in order.
    for (int i = 0; i < 3; i++) {
        char buf[64] = {0};
        ssize_t r = recv(sv[1], buf, sizeof(buf) - 1, 0);
        if (r != (ssize_t)strlen(payloads[i])) {
            printf("    recv[%d] returned %zd, want %zu\n", i, r,
                   strlen(payloads[i]));
        }
        check(r == (ssize_t)strlen(payloads[i]) && strcmp(buf, payloads[i]) == 0,
              "datagram arrives at peer with correct content");
    }

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 2: vlen == 0 returns 0 immediately, no errno, no work done.
// ---------------------------------------------------------------------------
static void test_vlen_zero(void) {
    puts("Test 2: sendmmsg with vlen == 0 returns 0");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    errno = 0;
    long n = sys_sendmmsg(sv[0], NULL, 0, 0);
    printf("  sendmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == 0, "vlen=0 returns 0");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 3: errno mapping for bad fd / bad msgvec pointer (when no message has
// been sent yet).
// ---------------------------------------------------------------------------
static void test_errno_paths(void) {
    puts("Test 3: sendmmsg errno on bad fd / bad msgvec pointer");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    errno = 0;
    long n = sys_sendmmsg(-1, NULL, 1, 0);
    printf("  fd=-1 vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EBADF, "bad fd returns EBADF");

    errno = 0;
    n = sys_sendmmsg(9999, NULL, 1, 0);
    printf("  fd=9999 vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EBADF, "unused fd returns EBADF");

    errno = 0;
    n = sys_sendmmsg(sv[0], NULL, 1, 0);
    printf("  fd=ok msgvec=NULL vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EFAULT, "NULL msgvec with vlen>0 returns EFAULT");

    close(sv[0]);
    close(sv[1]);
}

// ---------------------------------------------------------------------------
// Test 4: a per-message failure on the *first* message surfaces the errno. We
// build a valid header but with iov_base pointing at an unmapped address; the
// kernel must fail with EFAULT and not return a partial success.
// ---------------------------------------------------------------------------
static void test_first_message_fault(void) {
    puts("Test 4: sendmmsg reports EFAULT when the first message faults");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        exit(2);
    }

    struct iovec iov = {.iov_base = (void *)(uintptr_t)0x1, .iov_len = 16};
    struct mmsghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_hdr.msg_iov = &iov;
    hdr.msg_hdr.msg_iovlen = 1;

    errno = 0;
    long n = sys_sendmmsg(sv[0], &hdr, 1, 0);
    printf("  sendmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    check(n == -1 && errno == EFAULT,
          "first-message fault returns -1 with EFAULT");

    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    puts("sendmmsg parity test");
    test_three_messages();
    test_vlen_zero();
    test_errno_paths();
    test_first_message_fault();

    if (g_fail) {
        puts("\nRESULT: BUG(S) REPRODUCED");
        return 1;
    }
    puts("\nAll sendmmsg tests passed.");
    return 0;
}
