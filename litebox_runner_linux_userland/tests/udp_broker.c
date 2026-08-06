// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

enum {
    MAX_UDP_PAYLOAD = 65507,
};

static volatile sig_atomic_t sigpipe_count;

static void record_sigpipe(int signal_number) {
    if (signal_number == SIGPIPE) {
        ++sigpipe_count;
    }
}

static void wait_readable(int fd) {
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    assert(poll(&ready, 1, 5000) == 1);
    assert((ready.revents & POLLIN) != 0);
}

static void retract_readable(int fd) {
    unsigned char byte;
    assert(recv(fd, &byte, sizeof(byte), MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    assert(poll(&ready, 1, 0) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 3);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    assert(read(fd, NULL, 0) == 0);
    assert(readv(fd, NULL, 0) == 0);
    assert(writev(fd, NULL, 0) == 0);

    int enabled = 1;
    assert(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled,
                      sizeof(enabled)) == -1);
    assert(errno == ENOPROTOOPT);
    assert(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled,
                      sizeof(enabled)) == -1);
    assert(errno == EOPNOTSUPP);
    socklen_t enabled_length = sizeof(enabled);
    assert(getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled,
                      &enabled_length) == 0);
    assert(enabled == 0);

    struct pollfd writable = {.fd = fd, .events = POLLOUT};
    assert(poll(&writable, 1, 0) == 1);
    assert((writable.revents & POLLOUT) != 0);

    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)strtoul(argv[1], NULL, 10)),
    };
    assert(inet_pton(AF_INET, "127.0.0.1", &server.sin_addr) == 1);

    const char unconnected[] = "unconnected";
    assert(sendto(fd, unconnected, sizeof(unconnected) - 1, 0,
                  (const struct sockaddr *)&server, sizeof(server)) ==
           (ssize_t)(sizeof(unconnected) - 1));

    struct sockaddr_in local;
    socklen_t address_length = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &address_length) == 0);
    assert(local.sin_family == AF_INET);
    assert(local.sin_addr.s_addr == htonl(INADDR_ANY));
    assert(local.sin_port != 0);
    struct sockaddr_in peer;
    address_length = sizeof(peer);
    assert(getpeername(fd, (struct sockaddr *)&peer, &address_length) == -1);
    assert(errno == ENOTCONN);

    wait_readable(fd);
    assert(read(fd, NULL, 0) == 0);
    char truncated[4] = {0};
    struct iovec iov = {.iov_base = truncated, .iov_len = sizeof(truncated)};
    struct sockaddr_in source;
    struct msghdr message = {
        .msg_name = &source,
        .msg_namelen = sizeof(source),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    assert(recvmsg(fd, &message, 0) == sizeof(truncated));
    assert(memcmp(truncated, "0123", sizeof(truncated)) == 0);
    assert((message.msg_flags & MSG_TRUNC) != 0);
    assert(source.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(source.sin_port == server.sin_port);
    retract_readable(fd);

    const char read_request[] = "read";
    assert(sendto(fd, read_request, sizeof(read_request) - 1, 0,
                  (const struct sockaddr *)&server, sizeof(server)) ==
           (ssize_t)(sizeof(read_request) - 1));
    wait_readable(fd);
    memset(truncated, 0, sizeof(truncated));
    assert(read(fd, truncated, sizeof(truncated)) == sizeof(truncated));
    assert(memcmp(truncated, "abcd", sizeof(truncated)) == 0);
    retract_readable(fd);

    const char readv_request[] = "readv";
    assert(sendto(fd, readv_request, sizeof(readv_request) - 1, 0,
                  (const struct sockaddr *)&server, sizeof(server)) ==
           (ssize_t)(sizeof(readv_request) - 1));
    wait_readable(fd);
    int vector_fd = dup(fd);
    assert(vector_fd >= 0);
    char readv_first[2] = {0};
    char readv_second[2] = {0};
    struct iovec read_vector[] = {
        {
            .iov_base = readv_first,
            .iov_len = sizeof(readv_first),
        },
        {
            .iov_base = readv_second,
            .iov_len = sizeof(readv_second),
        },
    };
    assert(readv(vector_fd, read_vector, 2) ==
           sizeof(readv_first) + sizeof(readv_second));
    assert(memcmp(readv_first, "ab", sizeof(readv_first)) == 0);
    assert(memcmp(readv_second, "cd", sizeof(readv_second)) == 0);
    retract_readable(fd);

    const char readv_fault_request[] = "readv-fault";
    assert(sendto(fd, readv_fault_request, sizeof(readv_fault_request) - 1, 0,
                  (const struct sockaddr *)&server, sizeof(server)) ==
           (ssize_t)(sizeof(readv_fault_request) - 1));
    wait_readable(fd);
    memset(readv_first, 0, sizeof(readv_first));
    struct iovec faulting_read_vector[] = {
        {
            .iov_base = readv_first,
            .iov_len = sizeof(readv_first),
        },
        {
            .iov_base = (void *)1,
            .iov_len = sizeof(readv_second),
        },
    };
    assert(readv(vector_fd, faulting_read_vector, 2) == -1);
    assert(errno == EFAULT);
    assert(memcmp(readv_first, "ab", sizeof(readv_first)) == 0);
    retract_readable(fd);

    assert(sendto(fd, NULL, 0, 0, (const struct sockaddr *)&server,
                  sizeof(server)) == 0);
    wait_readable(fd);
    unsigned char empty = 0xff;
    memset(&source, 0xa5, sizeof(source));
    address_length = sizeof(source);
    assert(recvfrom(fd, &empty, sizeof(empty), 0,
                    (struct sockaddr *)&source, &address_length) == 0);
    assert(empty == 0xff);
    assert(address_length == sizeof(source));
    assert(source.sin_family == AF_INET);
    assert(source.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(source.sin_port == server.sin_port);
    retract_readable(fd);

    assert(connect(fd, (const struct sockaddr *)&server, sizeof(server)) == 0);
    address_length = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &address_length) == 0);
    assert(local.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(local.sin_port != 0);
    address_length = sizeof(peer);
    assert(getpeername(fd, (struct sockaddr *)&peer, &address_length) == 0);
    assert(peer.sin_addr.s_addr == server.sin_addr.s_addr);
    assert(peer.sin_port == server.sin_port);

    const char connected[] = "connected";
    assert(send(fd, connected, sizeof(connected) - 1, 0) ==
           (ssize_t)(sizeof(connected) - 1));
    wait_readable(fd);
    char reply[32] = {0};
    assert(recv(fd, reply, sizeof(reply), 0) == 15);
    assert(memcmp(reply, "connected-reply", 15) == 0);
    retract_readable(fd);

    const char writev_first[] = "write";
    const char writev_second[] = "v";
    struct iovec write_vector[] = {
        {
            .iov_base = (void *)writev_first,
            .iov_len = sizeof(writev_first) - 1,
        },
        {
            .iov_base = (void *)writev_second,
            .iov_len = sizeof(writev_second) - 1,
        },
    };
    assert(writev(vector_fd, write_vector, 2) == 6);
    wait_readable(fd);
    char writev_reply[16] = {0};
    assert(recv(fd, writev_reply, sizeof(writev_reply), 0) == 12);
    assert(memcmp(writev_reply, "writev-reply", 12) == 0);
    retract_readable(fd);
    assert(close(vector_fd) == 0);

    const char explicit[] = "explicit";
    assert(sendto(fd, explicit, sizeof(explicit) - 1, 0,
                  (const struct sockaddr *)&server, sizeof(server)) ==
           (ssize_t)(sizeof(explicit) - 1));
    wait_readable(fd);
    memset(reply, 0, sizeof(reply));
    assert(recv(fd, reply, sizeof(reply), 0) == 14);
    assert(memcmp(reply, "explicit-reply", 14) == 0);
    retract_readable(fd);

    unsigned char *maximum = malloc(MAX_UDP_PAYLOAD + 1);
    assert(maximum != NULL);
    memset(maximum, 0x5a, MAX_UDP_PAYLOAD);
    assert(send(fd, maximum, MAX_UDP_PAYLOAD, 0) == MAX_UDP_PAYLOAD);
    wait_readable(fd);
    memset(reply, 0, sizeof(reply));
    assert(recv(fd, reply, sizeof(reply), 0) == 13);
    assert(memcmp(reply, "maximum-reply", 13) == 0);
    retract_readable(fd);
    assert(send(fd, maximum, MAX_UDP_PAYLOAD + 1, 0) == -1);
    assert(errno == EMSGSIZE);
    free(maximum);

    struct sockaddr_in denied = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
    };
    assert(inet_pton(AF_INET, "192.0.2.1", &denied.sin_addr) == 1);
    assert(connect(fd, (const struct sockaddr *)&denied, sizeof(denied)) == -1);
    assert(errno == EACCES);
    address_length = sizeof(peer);
    assert(getpeername(fd, (struct sockaddr *)&peer, &address_length) == 0);
    assert(peer.sin_addr.s_addr == server.sin_addr.s_addr);
    assert(peer.sin_port == server.sin_port);

    int refused_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                            0);
    assert(refused_fd >= 0);
    struct sockaddr_in refused = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)strtoul(argv[2], NULL, 10)),
    };
    assert(inet_pton(AF_INET, "127.0.0.1", &refused.sin_addr) == 1);
    assert(connect(refused_fd, (const struct sockaddr *)&refused,
                   sizeof(refused)) == 0);

    const char preserved[] = "preserved";
    assert(send(fd, preserved, sizeof(preserved) - 1, 0) ==
           (ssize_t)(sizeof(preserved) - 1));
    wait_readable(fd);
    memset(reply, 0, sizeof(reply));
    assert(recv(fd, reply, sizeof(reply), 0) == 15);
    assert(memcmp(reply, "preserved-reply", 15) == 0);
    retract_readable(fd);

    assert(send(refused_fd, "x", 1, 0) == 1);
    struct pollfd failed = {.fd = refused_fd, .events = POLLERR};
    assert(poll(&failed, 1, 5000) == 1);
    assert((failed.revents & POLLERR) != 0);
    assert(recv(refused_fd, reply, sizeof(reply), 0) == -1);
    assert(errno == ECONNREFUSED);
    int socket_error = -1;
    socklen_t socket_error_length = sizeof(socket_error);
    assert(getsockopt(refused_fd, SOL_SOCKET, SO_ERROR, &socket_error,
                      &socket_error_length) == 0);
    assert(socket_error == 0);
    assert(close(refused_fd) == 0);

    assert(shutdown(fd, SHUT_WR) == 0);
    writable.revents = 0;
    assert(poll(&writable, 1, 0) == 1);
    assert((writable.revents & POLLOUT) != 0);
    assert(signal(SIGPIPE, record_sigpipe) != SIG_ERR);
    assert(writev(fd, write_vector, 2) == -1);
    assert(errno == EPIPE);
    assert(sigpipe_count == 0);
    assert(send(fd, connected, sizeof(connected) - 1, 0) == -1);
    assert(errno == EPIPE);
    assert(sigpipe_count == 0);

    assert(shutdown(fd, SHUT_RD) == 0);
    struct pollfd fully_shutdown = {
        .fd = fd,
        .events = POLLIN | POLLRDHUP | POLLHUP,
    };
    assert(poll(&fully_shutdown, 1, 0) == 1);
    assert((fully_shutdown.revents & POLLIN) != 0);
    assert((fully_shutdown.revents & POLLRDHUP) != 0);
    assert((fully_shutdown.revents & POLLHUP) != 0);
    assert(recv(fd, reply, sizeof(reply), 0) == -1);
    assert(errno == EAGAIN);
    int status_flags = fcntl(fd, F_GETFL);
    assert(status_flags >= 0);
    assert(fcntl(fd, F_SETFL, status_flags & ~O_NONBLOCK) == 0);
    struct timeval shutdown_timeout = {.tv_sec = 1};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &shutdown_timeout,
                      sizeof(shutdown_timeout)) == 0);
    assert(recv(fd, reply, sizeof(reply), 0) == 0);

    assert(close(fd) == 0);

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    assert(shutdown(fd, SHUT_RD) == -1);
    assert(errno == ENOTCONN);
    struct pollfd read_shutdown = {.fd = fd, .events = POLLIN | POLLRDHUP};
    assert(poll(&read_shutdown, 1, 0) == 1);
    assert((read_shutdown.revents & POLLIN) != 0);
    assert((read_shutdown.revents & POLLRDHUP) != 0);
    assert(recv(fd, reply, sizeof(reply), MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN);
    struct sockaddr_in bind_address = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    assert(bind(fd, (const struct sockaddr *)&bind_address,
                sizeof(bind_address)) == 0);
    address_length = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &address_length) == 0);
    assert(local.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(local.sin_port != 0);
    assert(close(fd) == 0);
    return 0;
}
