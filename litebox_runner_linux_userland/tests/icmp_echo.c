// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    assert(fd >= 0);
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    // Echo request with an odd-length payload and an identifier assigned by the socket.
    unsigned char request[] = {8, 0, 0, 0, 0, 0, 0, 42, 'a', 'b', 'c'};
    assert(sendto(fd, request, sizeof(request), 0, (struct sockaddr *)&dst, sizeof(dst)) ==
           sizeof(request));
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    assert(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN));
    unsigned char reply[64];
    struct sockaddr_in src;
    socklen_t len = sizeof(src);
    assert(recvfrom(fd, reply, sizeof(reply), 0, (struct sockaddr *)&src, &len) == sizeof(request));
    assert(src.sin_family == AF_INET && src.sin_addr.s_addr == dst.sin_addr.s_addr);
    assert(reply[0] == 0 && reply[1] == 0);
    assert(memcmp(reply + 6, request + 6, sizeof(request) - 6) == 0);
    struct sockaddr_in local;
    len = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &len) == 0);
    assert(local.sin_port != 0 && memcmp(reply + 4, &local.sin_port, 2) == 0);
    assert(close(fd) == 0);
}
