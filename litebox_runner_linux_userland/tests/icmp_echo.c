// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Largest ICMP message an IPv4 datagram carries: 0xffff less a 20-byte IP header.
#define MAX_ECHO_MESSAGE 65515

static int wait_readable(int fd) {
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    return poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN);
}

// An RFC 1071 sum over a message whose checksum field is set folds to all ones.
static int checksum_valid(const unsigned char *message, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2) {
        sum += (uint32_t)message[i] << 8 | (i + 1 < length ? message[i + 1] : 0);
    }
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum == 0xffff;
}

static void protocol_numbers_are_checked_in_full(void) {
    // -255 has the same low byte as IPPROTO_ICMP; Linux rejects IP protocol numbers outside
    // [0, IPPROTO_MAX) as invalid, and unknown ones inside it as unsupported.
    errno = 0;
    assert(socket(AF_INET, SOCK_DGRAM, -255) == -1 && errno == EINVAL);
    errno = 0;
    assert(socket(AF_INET, SOCK_DGRAM, 257) == -1 && errno == EPROTONOSUPPORT);
    errno = 0;
    assert(socket(AF_UNIX, SOCK_STREAM, -1) == -1 && errno == EPROTONOSUPPORT);
}

static void malformed_requests_are_rejected(int fd, const struct sockaddr_in *dst) {
    unsigned char request[] = {8, 0, 0, 0, 0, 0, 0, 1};
    const struct sockaddr *to = (const struct sockaddr *)dst;
    // Shorter than an ICMP header.
    errno = 0;
    assert(sendto(fd, request, sizeof(request) - 1, 0, to, sizeof(*dst)) == -1 && errno == EINVAL);
    // Not an echo request.
    request[0] = 3;
    errno = 0;
    assert(sendto(fd, request, sizeof(request), 0, to, sizeof(*dst)) == -1 && errno == EINVAL);
    request[0] = 8;
    request[1] = 1;
    errno = 0;
    assert(sendto(fd, request, sizeof(request), 0, to, sizeof(*dst)) == -1 && errno == EINVAL);
    unsigned char *large = calloc(1, MAX_ECHO_MESSAGE + 1);
    assert(large != NULL);
    large[0] = 8;
    errno = 0;
    assert(sendto(fd, large, MAX_ECHO_MESSAGE + 1, 0, to, sizeof(*dst)) == -1 && errno == EMSGSIZE);
    // The longest message is accepted and echoed in full, with a checksum that covers the
    // all-ones payload, whose sum carries out of 16 bits.
    memset(large + 8, 0xff, MAX_ECHO_MESSAGE - 8);
    assert(sendto(fd, large, MAX_ECHO_MESSAGE, 0, to, sizeof(*dst)) == MAX_ECHO_MESSAGE);
    assert(wait_readable(fd));
    memset(large, 0, MAX_ECHO_MESSAGE + 1);
    assert(recv(fd, large, MAX_ECHO_MESSAGE + 1, 0) == MAX_ECHO_MESSAGE);
    assert(large[0] == 0 && large[8] == 0xff && large[MAX_ECHO_MESSAGE - 1] == 0xff);
    assert(checksum_valid(large, MAX_ECHO_MESSAGE));
    free(large);
}

// Like a Linux ping socket, a connected one receives replies from any peer it sends to, keeps
// queued replies when it connects elsewhere, and reports the port it was connected with.
static void connected_socket_accepts_any_reply(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);
    assert(fd >= 0);
    struct sockaddr_in first = {
        .sin_family = AF_INET, .sin_port = htons(7), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in second = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000002)};
    assert(connect(fd, (struct sockaddr *)&first, sizeof(first)) == 0);
    struct sockaddr_in peer;
    socklen_t len = sizeof(peer);
    assert(getpeername(fd, (struct sockaddr *)&peer, &len) == 0);
    assert(peer.sin_addr.s_addr == first.sin_addr.s_addr && peer.sin_port == htons(7));
    unsigned char request[] = {8, 0, 0, 0, 0, 0, 0, 1};
    assert(send(fd, request, sizeof(request), 0) == sizeof(request));
    request[7]++;
    assert(sendto(fd, request, sizeof(request), 0, (struct sockaddr *)&second, sizeof(second)) ==
           sizeof(request));
    assert(connect(fd, (struct sockaddr *)&second, sizeof(second)) == 0);
    for (unsigned char sequence = 1; sequence <= 2; sequence++) {
        unsigned char reply[16];
        struct sockaddr_in src;
        len = sizeof(src);
        assert(wait_readable(fd));
        assert(recvfrom(fd, reply, sizeof(reply), 0, (struct sockaddr *)&src, &len) ==
               sizeof(request));
        assert(reply[7] == sequence);
        assert(src.sin_addr.s_addr == (sequence == 1 ? first : second).sin_addr.s_addr);
    }
    assert(close(fd) == 0);
}

// Any IP socket reports an empty extended error queue as EAGAIN.
static void tcp_has_no_extended_errors(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    unsigned char ignored[1];
    errno = 0;
    assert(recv(fd, ignored, sizeof(ignored), MSG_ERRQUEUE) == -1 && errno == EAGAIN);
    assert(close(fd) == 0);
}

int main(void) {
    protocol_numbers_are_checked_in_full();
    tcp_has_no_extended_errors();
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
    assert(wait_readable(fd));
    // There is no extended error queue to read, and asking leaves the replies queued.
    unsigned char ignored[1];
    errno = 0;
    assert(recv(fd, ignored, sizeof(ignored), MSG_ERRQUEUE) == -1 && errno == EAGAIN);
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
    assert(checksum_valid(reply, sizeof(request)));
    assert(memcmp(prefix, reply, iov.iov_len) == 0 && reply[7] == 42);
    assert(memcmp(reply + 8, request + 8, sizeof(request) - 8) == 0);
    struct sockaddr_in local;
    len = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &len) == 0);
    assert(local.sin_port != 0 && memcmp(reply + 4, &local.sin_port, 2) == 0);
    assert(wait_readable(fd));
    assert(recv(fd, reply, sizeof(reply), 0) == sizeof(request));
    assert(checksum_valid(reply, sizeof(request)));
    assert(memcmp(reply + 6, request + 6, sizeof(request) - 6) == 0);
    assert(recv(fd, reply, sizeof(reply), 0) == -1 && errno == EAGAIN);
    malformed_requests_are_rejected(fd, &dst);
    assert(close(fd) == 0);
    connected_socket_accepts_any_reply();
}
