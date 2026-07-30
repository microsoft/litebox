// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

enum {
    REQUEST_SIZE = 65536,
    RESPONSE_SIZE = 40000,
    BACKPRESSURE_SIZE = 8 * 1024 * 1024,
};

int main(int argc, char **argv) {
    assert(argc == 3);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    assert(fd >= 0);

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)strtoul(argv[1], NULL, 10)),
    };
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    int result = connect(fd, (const struct sockaddr *)&address, sizeof(address));
    assert(result == 0 || (result == -1 && errno == EINPROGRESS));

    if (result == -1) {
        struct sockaddr_in connecting_address;
        socklen_t connecting_address_length = sizeof(connecting_address);
        assert(getsockname(fd, (struct sockaddr *)&connecting_address,
                           &connecting_address_length) == 0);
        assert(connecting_address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        assert(connecting_address.sin_port != 0);
        int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        assert(epoll_fd >= 0);
        struct epoll_event interest = {.events = EPOLLOUT, .data.fd = fd};
        assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &interest) == 0);
        struct epoll_event ready;
        assert(epoll_wait(epoll_fd, &ready, 1, 5000) == 1);
        assert((ready.events & (EPOLLOUT | EPOLLERR)) != 0);
        assert(close(epoll_fd) == 0);
        int socket_error = -1;
        socklen_t error_length = sizeof(socket_error);
        assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) == 0);
        assert(socket_error == 0);
    }
    struct sockaddr_in local_address;
    socklen_t address_length = sizeof(local_address);
    assert(getsockname(fd, (struct sockaddr *)&local_address, &address_length) == 0);
    assert(local_address.sin_family == AF_INET);
    assert(local_address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(local_address.sin_port != 0);
    struct sockaddr_in peer_address;
    address_length = sizeof(peer_address);
    assert(getpeername(fd, (struct sockaddr *)&peer_address, &address_length) == 0);
    assert(peer_address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(peer_address.sin_port == address.sin_port);
    int option = 1;
    assert(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option)) == 0);
    assert(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &option, sizeof(option)) == 0);
    option = 30;
    assert(setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &option, sizeof(option)) == 0);
    struct linger linger = {.l_onoff = 1, .l_linger = 0};
    assert(setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) == -1);
    assert(errno == EOPNOTSUPP);

    unsigned char request[REQUEST_SIZE];
    memset(request, 0x5a, sizeof(request));
    size_t sent = 0;
    while (sent != sizeof(request)) {
        ssize_t count = send(fd, request + sent, sizeof(request) - sent, MSG_NOSIGNAL);
        if (count == -1) {
            assert(errno == EAGAIN);
            struct pollfd poll_fd = {.fd = fd, .events = POLLOUT};
            assert(poll(&poll_fd, 1, 5000) == 1);
            continue;
        }
        assert(count > 0);
        sent += (size_t)count;
    }

    unsigned char response[RESPONSE_SIZE];
    assert(recv(fd, response, sizeof(response), 0) == -1);
    assert(errno == EAGAIN);

    int flags = fcntl(fd, F_GETFL);
    assert(flags >= 0);
    assert(fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0);

    struct timeval timeout = {.tv_sec = 0, .tv_usec = 20000};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(recv(fd, response, sizeof(response), 0) == -1);
    assert(errno == EAGAIN);
    timeout.tv_usec = 0;
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);

    unsigned char discarded[16];
    memset(discarded, 0xff, sizeof(discarded));
    assert(recv(fd, discarded, sizeof(discarded), MSG_TRUNC) == sizeof(discarded));
    for (size_t i = 0; i < sizeof(discarded); ++i) {
        assert(discarded[i] == 0xff);
    }

    size_t received = 0;
    while (received != sizeof(response)) {
        ssize_t count = recv(fd, response + received, sizeof(response) - received, 0);
        assert(count > 0);
        received += (size_t)count;
    }
    for (size_t i = 0; i < sizeof(response); ++i) {
        assert(response[i] == 0xa5);
    }
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    assert(epoll_fd >= 0);
    struct epoll_event interest = {.events = EPOLLRDHUP, .data.fd = fd};
    assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &interest) == 0);
    struct epoll_event ready;
    assert(epoll_wait(epoll_fd, &ready, 1, 5000) == 1);
    assert((ready.events & EPOLLRDHUP) != 0);
    assert(close(epoll_fd) == 0);

    unsigned char *backpressure = malloc(BACKPRESSURE_SIZE);
    assert(backpressure != NULL);
    memset(backpressure, 0x3c, BACKPRESSURE_SIZE);
    sent = 0;
    while (sent != BACKPRESSURE_SIZE) {
        ssize_t count =
            send(fd, backpressure + sent, BACKPRESSURE_SIZE - sent, MSG_NOSIGNAL);
        if (count <= 0) {
            perror("blocking broker send");
            abort();
        }
        sent += (size_t)count;
    }
    free(backpressure);

    assert(shutdown(fd, SHUT_WR) == 0);
    struct pollfd shutdown_poll = {.fd = fd, .events = POLLOUT};
    assert(poll(&shutdown_poll, 1, 0) == 1);
    assert((shutdown_poll.revents & POLLOUT) != 0);
    assert(send(fd, request, 1, MSG_NOSIGNAL) == -1);
    assert(errno == EPIPE);
    assert(recv(fd, response, sizeof(response), 0) == 0);
    assert(close(fd) == 0);

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    assert(connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0);
    struct pollfd reset_poll = {.fd = fd, .events = POLLIN};
    assert(poll(&reset_poll, 1, 5000) == 1);
    assert((reset_poll.revents & POLLERR) != 0);
    reset_poll.revents = 0;
    assert(poll(&reset_poll, 1, 0) == 1);
    assert((reset_poll.revents & POLLERR) != 0);
    int socket_error = 0;
    socklen_t error_length = sizeof(socket_error);
    assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) == 0);
    assert(socket_error == ECONNRESET);
    assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) == 0);
    assert(socket_error == 0);
    reset_poll.revents = 0;
    assert(poll(&reset_poll, 1, 0) >= 0);
    assert((reset_poll.revents & POLLERR) == 0);
    assert(close(fd) == 0);

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    assert(connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0);
    unsigned char reset_byte;
    assert(recv(fd, &reset_byte, sizeof(reset_byte), 0) == -1);
    assert(errno == ECONNRESET);
    socket_error = -1;
    error_length = sizeof(socket_error);
    assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) == 0);
    assert(socket_error == 0);
    reset_poll.fd = fd;
    reset_poll.revents = 0;
    assert(poll(&reset_poll, 1, 0) >= 0);
    assert((reset_poll.revents & POLLERR) == 0);
    assert(close(fd) == 0);

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    address.sin_port = htons((uint16_t)strtoul(argv[2], NULL, 10));
    result = connect(fd, (const struct sockaddr *)&address, sizeof(address));
    assert(result == -1);
    if (errno == EINPROGRESS) {
        struct pollfd poll_fd = {.fd = fd, .events = POLLOUT};
        assert(poll(&poll_fd, 1, 5000) == 1);
        socket_error = 0;
        error_length = sizeof(socket_error);
        assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) == 0);
        assert(socket_error == ECONNREFUSED);
        poll_fd.revents = 0;
        assert(poll(&poll_fd, 1, 0) == 1);
        assert((poll_fd.revents & POLLERR) == 0);
        assert((poll_fd.revents & (POLLIN | POLLOUT | POLLHUP)) != 0);
    } else {
        assert(errno == ECONNREFUSED);
    }
    assert(close(fd) == 0);

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    assert(inet_pton(AF_INET, "192.0.2.1", &address.sin_addr) == 1);
    address.sin_port = htons(80);
    assert(connect(fd, (const struct sockaddr *)&address, sizeof(address)) == -1);
    assert(errno == EACCES);
    assert(close(fd) == 0);
    return 0;
}
