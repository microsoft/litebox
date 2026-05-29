// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <stdint.h>
#include <sys/uio.h>

// Use the raw syscall so we exercise exactly what LiteBox intercepts; glibc's
// wrapper would otherwise be free to massage arguments before reaching the
// kernel.
static long raw_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen,
                         int flags) {
    return syscall(SYS_sendmmsg, fd, msgvec, vlen, flags);
}

static void test_three_messages(void) {
    puts("Test 1: sendmmsg sends multiple datagrams and reports per-entry msg_len");

    int sv[2];
    make_socket_pair(SOCK_DGRAM, sv);

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
    long n = raw_sendmmsg(sv[0], hdrs, 3, 0);
    printf("  sendmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    TEST_ASSERT(n == 3, "sendmmsg returned 3");
    for (int i = 0; i < 3; i++) {
        unsigned int got = hdrs[i].msg_len;
        unsigned int want = (unsigned int)strlen(payloads[i]);
        TEST_ASSERT(got == want, "msg_len matches payload length for each entry");
    }

    for (int i = 0; i < 3; i++) {
        expect_recv_string(sv[1], payloads[i], "datagram arrives at peer with correct content");
    }

    close_pair(sv);
}

static void test_zero_length_message(void) {
    puts("Test 2: sendmmsg sends an entry with msg_iovlen == 0");

    int sv[2];
    make_socket_pair(SOCK_DGRAM, sv);

    struct mmsghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_len = 0xDEADBEEF;

    errno = 0;
    long n = raw_sendmmsg(sv[0], &hdr, 1, 0);
    printf("  sendmmsg returned %ld (errno=%d %s), msg_len=%u\n", n,
           errno, n < 0 ? strerror(errno) : "-", hdr.msg_len);
    TEST_ASSERT(n == 1, "zero-length message counts as one sent message");
    TEST_ASSERT(hdr.msg_len == 0, "zero-length message reports msg_len == 0");

    char buf[1] = {0x7f};
    errno = 0;
    ssize_t r = recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT);
    printf("  recv returned %zd (errno=%d %s)\n", r, errno,
           r < 0 ? strerror(errno) : "-");
    TEST_ASSERT(r == 0, "peer receives a zero-length datagram");

    close_pair(sv);
}

static void test_multi_iov_datagram(void) {
    puts("Test 3: sendmmsg gathers multiple iovecs into one datagram");

    int sv[2];
    make_socket_pair(SOCK_DGRAM, sv);

    const char first[] = "multi-";
    const char second[] = "iov";
    const char expected[] = "multi-iov";
    struct iovec iov[2] = {
        {.iov_base = (void *)first, .iov_len = strlen(first)},
        {.iov_base = (void *)second, .iov_len = strlen(second)},
    };
    struct mmsghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_hdr.msg_iov = iov;
    hdr.msg_hdr.msg_iovlen = 2;
    hdr.msg_len = 0xDEADBEEF;

    errno = 0;
    long n = raw_sendmmsg(sv[0], &hdr, 1, 0);
    printf("  sendmmsg returned %ld (errno=%d %s), msg_len=%u\n", n,
           errno, n < 0 ? strerror(errno) : "-", hdr.msg_len);
    TEST_ASSERT(n == 1, "multi-iov datagram counts as one sent message");
    TEST_ASSERT(hdr.msg_len == strlen(expected),
                "multi-iov datagram reports total payload length");

    char buf[32] = {0};
    errno = 0;
    ssize_t r = recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT);
    printf("  recv returned %zd (errno=%d %s), payload='%s'\n", r, errno,
           r < 0 ? strerror(errno) : "-", r >= 0 ? buf : "");
    TEST_ASSERT(r == (ssize_t)strlen(expected) && strcmp(buf, expected) == 0,
                "peer receives one gathered datagram");

    close_pair(sv);
}

static void test_vlen_zero(void) {
    puts("Test 4: sendmmsg with vlen == 0 returns 0");

    int sv[2];
    make_socket_pair(SOCK_DGRAM, sv);

    errno = 0;
    long n = raw_sendmmsg(sv[0], NULL, 0, 0);
    printf("  sendmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    TEST_ASSERT(n == 0, "vlen=0 returns 0");

    close_pair(sv);
}

static void test_errno_paths(void) {
    puts("Test 5: sendmmsg errno on bad fd / bad msgvec pointer");

    int sv[2];
    make_socket_pair(SOCK_DGRAM, sv);

    errno = 0;
    long n = raw_sendmmsg(-1, NULL, 1, 0);
    printf("  fd=-1 vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    TEST_ASSERT(n == -1 && errno == EBADF, "bad fd returns EBADF");

    errno = 0;
    n = raw_sendmmsg(9999, NULL, 1, 0);
    printf("  fd=9999 vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    TEST_ASSERT(n == -1 && errno == EBADF, "unused fd returns EBADF");

    errno = 0;
    n = raw_sendmmsg(sv[0], NULL, 1, 0);
    printf("  fd=ok msgvec=NULL vlen=1: ret=%ld errno=%d (%s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    TEST_ASSERT(n == -1 && errno == EFAULT,
                "NULL msgvec with vlen>0 returns EFAULT");

    close_pair(sv);
}

static void test_first_message_fault(void) {
    puts("Test 6: sendmmsg reports EFAULT when the first message faults");

    int sv[2];
    make_socket_pair(SOCK_DGRAM, sv);

    struct iovec iov = {.iov_base = (void *)(uintptr_t)0x1, .iov_len = 16};
    struct mmsghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_hdr.msg_iov = &iov;
    hdr.msg_hdr.msg_iovlen = 1;

    errno = 0;
    long n = raw_sendmmsg(sv[0], &hdr, 1, 0);
    printf("  sendmmsg returned %ld (errno=%d %s)\n", n, errno,
           n < 0 ? strerror(errno) : "-");
    TEST_ASSERT(n == -1 && errno == EFAULT,
                "first-message fault returns -1 with EFAULT");

    close_pair(sv);
}

int main(void) {
    puts("sendmmsg parity test");
    test_three_messages();
    test_zero_length_message();
    test_multi_iov_datagram();
    test_vlen_zero();
    test_errno_paths();
    test_first_message_fault();

    puts("\nAll sendmmsg tests passed.");
    return 0;
}
