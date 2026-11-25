// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks how `sendmsg` handles control messages on each kind of socket: every socket copies the
// control bytes after the data's iovec, then TCP and UDP sockets ignore the messages only Unix
// sockets act on, and the levels they don't parse, while rejecting malformed messages and
// unknown types.

#define _GNU_SOURCE
#include "helpers.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOL_UDP
#define SOL_UDP 17
#endif

static int tcp_sender, tcp_receiver, udp_sender, udp_receiver, unix_sender, unix_receiver;

// Bounds every receive from `fd`, so a send that reported success without delivering fails the
// test instead of hanging it.
static void bound_receives(int fd) {
    struct timeval timeout = {.tv_sec = 10};
    TEST_ASSERT(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "setsockopt(SO_RCVTIMEO)");
}

static void make_sockets(void) {
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listener >= 0, "socket(TCP)");
    TEST_ASSERT(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0, "bind(TCP)");
    TEST_ASSERT(listen(listener, 1) == 0, "listen");
    TEST_ASSERT(getsockname(listener, (struct sockaddr *)&address, &length) == 0, "getsockname");
    tcp_sender = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(tcp_sender >= 0, "socket(TCP)");
    TEST_ASSERT(connect(tcp_sender, (struct sockaddr *)&address, sizeof(address)) == 0,
                "connect(TCP)");
    tcp_receiver = accept(listener, NULL, NULL);
    TEST_ASSERT(tcp_receiver >= 0, "accept");
    close(listener);

    address.sin_port = 0;
    length = sizeof(address);
    udp_receiver = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(udp_receiver >= 0, "socket(UDP)");
    TEST_ASSERT(bind(udp_receiver, (struct sockaddr *)&address, sizeof(address)) == 0,
                "bind(UDP)");
    TEST_ASSERT(getsockname(udp_receiver, (struct sockaddr *)&address, &length) == 0,
                "getsockname");
    udp_sender = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(udp_sender >= 0, "socket(UDP)");
    TEST_ASSERT(connect(udp_sender, (struct sockaddr *)&address, sizeof(address)) == 0,
                "connect(UDP)");

    int pair[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair");
    unix_sender = pair[0];
    unix_receiver = pair[1];
    bound_receives(tcp_receiver);
    bound_receives(udp_receiver);
    bound_receives(unix_receiver);
}

// Sends one byte over `fd` with the `length` control bytes at `control`, returning `sendmsg`'s
// result.
static ssize_t send_control(int fd, void *control, size_t length) {
    struct iovec iov = {.iov_base = "x", .iov_len = 1};
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = length};
    return sendmsg(fd, &msg, MSG_DONTWAIT);
}

// Sends one byte over `fd` with a single control message of `level` and `type` carrying
// `data_length` bytes of `data`, returning `sendmsg`'s result.
static ssize_t send_message(int fd, int level, int type, const void *data, size_t data_length) {
    union {
        struct cmsghdr header;
        char bytes[CMSG_SPACE(16)];
    } control;
    memset(&control, 0, sizeof(control));
    TEST_ASSERT(data_length <= 16, "control data too long");
    control.header.cmsg_level = level;
    control.header.cmsg_type = type;
    control.header.cmsg_len = CMSG_LEN(data_length);
    memcpy(CMSG_DATA(&control.header), data, data_length);
    return send_control(fd, &control, CMSG_SPACE(data_length));
}

// Checks that the byte a successful send carried reached `receiver`.
static void expect_received(int receiver) {
    char byte = 0;
    TEST_ASSERT(recv(receiver, &byte, 1, 0) == 1 && byte == 'x', "receive the sent byte");
}

// Checks that sending a message of `level` and `type` over `fd` succeeds and reaches `receiver`.
static void expect_ignored(int fd, int receiver, int level, int type, const char *what) {
    int value = -1;
    errno = 0;
    if (send_message(fd, level, type, &value, sizeof(value)) != 1) {
        printf("FAIL: %s: sendmsg failed with errno %d\n", what, errno);
        exit(1);
    }
    expect_received(receiver);
}

// Checks that sending a message of `level` and `type` over `fd` fails with `expected`.
static void expect_rejected(int fd, int level, int type, int expected, const char *what) {
    int value = -1;
    errno = 0;
    if (send_message(fd, level, type, &value, sizeof(value)) != -1 || errno != expected) {
        printf("FAIL: %s: errno %d, expected %d\n", what, errno, expected);
        exit(1);
    }
}

static void test_tcp_ignores_other_levels_and_unix_messages(void) {
    expect_ignored(tcp_sender, tcp_receiver, SOL_IP, IP_TOS, "TCP SOL_IP");
    expect_ignored(tcp_sender, tcp_receiver, SOL_UDP, 999, "TCP SOL_UDP");
    expect_ignored(tcp_sender, tcp_receiver, 999, 1, "TCP unknown level");
    // Not a descriptor, which TCP never looks at.
    expect_ignored(tcp_sender, tcp_receiver, SOL_SOCKET, SCM_RIGHTS, "TCP SCM_RIGHTS");
    int credentials[3] = {getpid(), getuid(), getgid()};
    TEST_ASSERT(send_message(tcp_sender, SOL_SOCKET, SCM_CREDENTIALS, credentials,
                             sizeof(credentials)) == 1,
                "TCP SCM_CREDENTIALS");
    expect_received(tcp_receiver);
}

static void test_tcp_rejects_unknown_socket_messages(void) {
    expect_rejected(tcp_sender, SOL_SOCKET, 999, EINVAL, "TCP unknown SOL_SOCKET type");
}

static void test_udp_ignores_other_levels_and_unix_messages(void) {
    expect_ignored(udp_sender, udp_receiver, SOL_IPV6, 999, "UDP SOL_IPV6");
    expect_ignored(udp_sender, udp_receiver, 999, 1, "UDP unknown level");
    expect_ignored(udp_sender, udp_receiver, SOL_SOCKET, SCM_RIGHTS, "UDP SCM_RIGHTS");
    int credentials[3] = {getpid(), getuid(), getgid()};
    TEST_ASSERT(send_message(udp_sender, SOL_SOCKET, SCM_CREDENTIALS, credentials,
                             sizeof(credentials)) == 1,
                "UDP SCM_CREDENTIALS");
    expect_received(udp_receiver);
}

static void test_udp_rejects_unknown_types(void) {
    expect_rejected(udp_sender, SOL_SOCKET, 999, EINVAL, "UDP unknown SOL_SOCKET type");
    expect_rejected(udp_sender, SOL_IP, 999, EINVAL, "UDP unknown SOL_IP type");
    expect_rejected(udp_sender, SOL_UDP, 999, EINVAL, "UDP unknown SOL_UDP type");
}

static void test_unix_rejects_unknown_socket_messages(void) {
    expect_ignored(unix_sender, unix_receiver, SOL_IP, IP_TOS, "Unix SOL_IP");
    expect_rejected(unix_sender, SOL_SOCKET, 999, EINVAL, "Unix unknown SOL_SOCKET type");
}

// Fills `control` with a message of level 999, then one of `level` and `type`, then bytes too
// few for a header, returning the control length.
static size_t two_messages(char *control, size_t capacity, int level, int type) {
    size_t length = 2 * CMSG_SPACE(sizeof(int)) + sizeof(struct cmsghdr) - 1;
    TEST_ASSERT(length <= capacity, "control buffer too small");
    memset(control, 0, capacity);
    struct msghdr msg = {.msg_control = control, .msg_controllen = length};
    struct cmsghdr *message = CMSG_FIRSTHDR(&msg);
    message->cmsg_level = 999;
    message->cmsg_type = 1;
    message->cmsg_len = CMSG_LEN(sizeof(int));
    message = CMSG_NXTHDR(&msg, message);
    TEST_ASSERT(message != NULL, "second message");
    message->cmsg_level = level;
    message->cmsg_type = type;
    message->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(message) = -1;
    return length;
}

static void test_every_message_is_parsed(void) {
    union {
        struct cmsghdr header;
        char bytes[3 * CMSG_SPACE(sizeof(int))];
    } control;
    size_t length = two_messages(control.bytes, sizeof(control), SOL_SOCKET, SCM_RIGHTS);
    TEST_ASSERT(send_control(tcp_sender, &control, length) == 1,
                "TCP ignores both messages and the trailing bytes");
    expect_received(tcp_receiver);
    errno = 0;
    TEST_ASSERT(send_control(unix_sender, &control, length) == -1 && errno == EBADF,
                "Unix rejects the second message's descriptor");
    length = two_messages(control.bytes, sizeof(control), SOL_UDP, 999);
    errno = 0;
    TEST_ASSERT(send_control(udp_sender, &control, length) == -1 && errno == EINVAL,
                "UDP rejects the second message's type");
}

static void test_sendmmsg_parses_each_message(void) {
    union {
        struct cmsghdr header;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    control.header.cmsg_level = SOL_IP;
    control.header.cmsg_type = 999;
    control.header.cmsg_len = CMSG_LEN(sizeof(int));
    struct iovec iov = {.iov_base = "x", .iov_len = 1};
    struct mmsghdr messages[1] = {{.msg_hdr = {.msg_iov = &iov,
                                               .msg_iovlen = 1,
                                               .msg_control = &control,
                                               .msg_controllen = sizeof(control)}}};
    TEST_ASSERT(sendmmsg(tcp_sender, messages, 1, 0) == 1, "TCP ignores SOL_IP");
    expect_received(tcp_receiver);
    errno = 0;
    TEST_ASSERT(sendmmsg(udp_sender, messages, 1, 0) == -1 && errno == EINVAL,
                "UDP rejects an unknown SOL_IP type");
}

static void test_malformed_messages(void) {
    int sockets[] = {tcp_sender, udp_sender, unix_sender};
    for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i++) {
        union {
            struct cmsghdr header;
            char bytes[CMSG_SPACE(sizeof(int))];
        } control;
        memset(&control, 0, sizeof(control));
        control.header.cmsg_level = 999;
        control.header.cmsg_len = sizeof(control.header) - 1;
        errno = 0;
        TEST_ASSERT(send_control(sockets[i], &control, sizeof(control)) == -1 && errno == EINVAL,
                    "a message shorter than its header");
        control.header.cmsg_len = sizeof(control) + 1;
        errno = 0;
        TEST_ASSERT(send_control(sockets[i], &control, sizeof(control)) == -1 && errno == EINVAL,
                    "a message longer than the control bytes");
    }
}

static void test_every_socket_copies_control_bytes(void) {
    int senders[] = {tcp_sender, udp_sender, unix_sender};
    int receivers[] = {tcp_receiver, udp_receiver, unix_receiver};
    for (size_t i = 0; i < sizeof(senders) / sizeof(senders[0]); i++) {
        // Too short for a message, but still copied.
        char short_control[sizeof(struct cmsghdr) - 1] = {0};
        TEST_ASSERT(send_control(senders[i], short_control, sizeof(short_control)) == 1,
                    "control bytes too short for a message");
        expect_received(receivers[i]);
        errno = 0;
        TEST_ASSERT(send_control(senders[i], (void *)1, sizeof(short_control)) == -1 &&
                        errno == EFAULT,
                    "unreadable control bytes too short for a message");

        // Larger than Linux accepts whatever its `optmem_max`, so not read.
        errno = 0;
        TEST_ASSERT(send_control(senders[i], short_control, (size_t)INT_MAX + 1) == -1 &&
                        errno == ENOBUFS,
                    "too many control bytes");
        // Copied, then rejected as malformed for its zero length.
        char *control = calloc(1, 4096);
        TEST_ASSERT(control != NULL, "calloc");
        errno = 0;
        TEST_ASSERT(send_control(senders[i], control, 4096) == -1 && errno == EINVAL,
                    "a page of zeroed control bytes");
        free(control);
    }
}

static void test_iovec_errors_precede_control_errors(void) {
    struct iovec iov = {.iov_base = "x", .iov_len = 1};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = IOV_MAX + 1,
                         .msg_control = (void *)1,
                         .msg_controllen = sizeof(struct cmsghdr)};
    errno = 0;
    TEST_ASSERT(sendmsg(udp_sender, &msg, 0) == -1 && errno == EMSGSIZE,
                "too many iovecs and unreadable control bytes");
    errno = 0;
    TEST_ASSERT(sendmsg(unix_sender, &msg, 0) == -1 && errno == EMSGSIZE,
                "too many iovecs and unreadable control bytes over a Unix socket");
}

// Checks that `sendmsg` treats a destination of length zero as none, and parses an inet socket's
// destination only after checking the iovec.
static void test_inet_destination(void) {
    struct sockaddr_in destination = {.sin_family = 12345};
    struct iovec iov = {.iov_base = "x", .iov_len = 1};
    struct msghdr msg = {.msg_name = &destination, .msg_iov = &iov, .msg_iovlen = 1};
    TEST_ASSERT(sendmsg(udp_sender, &msg, 0) == 1, "a destination of length zero");
    expect_received(udp_receiver);

    msg.msg_namelen = sizeof(destination);
    msg.msg_iovlen = IOV_MAX + 1;
    errno = 0;
    TEST_ASSERT(sendmsg(udp_sender, &msg, 0) == -1 && errno == EMSGSIZE,
                "too many iovecs and an unknown address family");
    msg.msg_iovlen = 1;
    errno = 0;
    TEST_ASSERT(sendmsg(udp_sender, &msg, 0) == -1 && errno == EAFNOSUPPORT,
                "an unknown address family");
}

int main(void) {
    printf("Testing sendmsg control messages\n");
    // A watchdog, so a hang fails the test.
    alarm(60);
    make_sockets();
    test_tcp_ignores_other_levels_and_unix_messages();
    test_tcp_rejects_unknown_socket_messages();
    test_udp_ignores_other_levels_and_unix_messages();
    test_udp_rejects_unknown_types();
    test_unix_rejects_unknown_socket_messages();
    test_every_message_is_parsed();
    test_sendmmsg_parses_each_message();
    test_malformed_messages();
    test_every_socket_copies_control_bytes();
    test_iovec_errors_precede_control_errors();
    test_inet_destination();
    printf("All sendmsg control message tests passed.\n");
    return 0;
}
