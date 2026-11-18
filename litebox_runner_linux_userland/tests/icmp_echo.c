// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    // The full protocol integer matters: -255 has the same low byte as IPPROTO_ICMP.
    assert(socket(AF_INET, SOCK_DGRAM, -255) == -1);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);
    assert(fd >= 0);
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    // Echo request with an odd-length payload and an identifier assigned by the socket.
    unsigned char request[] = {8, 0, 0, 0, 0, 0, 0, 42, 'a', 'b', 'c'};
    assert(sendto(fd, request, sizeof(request), 0, (struct sockaddr *)&dst, sizeof(dst)) ==
           sizeof(request));
    request[7]++;
    assert(sendto(fd, request, sizeof(request), 0, (struct sockaddr *)&dst, sizeof(dst)) ==
           sizeof(request));
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    assert(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN));
    unsigned char prefix[9];
    memset(prefix, 0xff, sizeof(prefix));
    struct iovec iov = {.iov_base = prefix, .iov_len = sizeof(prefix) - 1};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    // Unlike UDP, Linux ping sockets return the bytes copied, even with input MSG_TRUNC.
    assert(recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC) == (ssize_t)iov.iov_len);
    assert(msg.msg_flags == MSG_TRUNC);
    assert(prefix[8] == 0xff);
    unsigned char reply[64];
    struct sockaddr_in src;
    socklen_t len = sizeof(src);
    assert(recvfrom(fd, reply, sizeof(reply), 0, (struct sockaddr *)&src, &len) == sizeof(request));
    assert(src.sin_family == AF_INET && src.sin_addr.s_addr == dst.sin_addr.s_addr);
    assert(reply[0] == 0 && reply[1] == 0);
    assert(memcmp(prefix, reply, iov.iov_len) == 0 && reply[7] == 42);
    assert(memcmp(reply + 8, request + 8, sizeof(request) - 8) == 0);
    struct sockaddr_in local;
    len = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &len) == 0);
    assert(local.sin_port != 0 && memcmp(reply + 4, &local.sin_port, 2) == 0);
    assert(recv(fd, reply, sizeof(reply), 0) == sizeof(request));
    assert(memcmp(reply + 6, request + 6, sizeof(request) - 6) == 0);
    assert(recv(fd, reply, sizeof(reply), 0) == -1 && errno == EAGAIN);
    assert(close(fd) == 0);
}
