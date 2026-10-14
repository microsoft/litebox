// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks how TCP sockets that are not, or are no longer, connected report
// readiness, receives, sends, and pending errors.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
    UNCONNECTED_EVENTS = POLLOUT | POLLHUP,
    CLOSED_EVENTS = POLLIN | POLLOUT | POLLHUP | POLLRDHUP,
};

static struct sockaddr_in gateway_address(const char *port) {
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)strtoul(port, NULL, 10)),
    };
    assert(inet_pton(AF_INET, "10.0.2.1", &address.sin_addr) == 1);
    return address;
}

static int tcp_socket(int flags) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | flags, 0);
    assert(fd >= 0);
    return fd;
}

static int connect_to(const struct sockaddr_in *address, int flags) {
    int fd = tcp_socket(flags);
    int result = connect(fd, (const struct sockaddr *)address, sizeof(*address));
    if (flags & SOCK_NONBLOCK) {
        assert(result == -1 && errno == EINPROGRESS);
    } else {
        assert(result == 0);
    }
    return fd;
}

static void wait_for(int fd, short events) {
    struct pollfd poll_fd = {.fd = fd, .events = events};
    assert(poll(&poll_fd, 1, 5000) == 1);
}

// The peer resets the connection once it receives a byte.
static int connect_and_reset(const struct sockaddr_in *address) {
    int fd = connect_to(address, 0);
    unsigned char byte = 0;
    assert(send(fd, &byte, sizeof(byte), MSG_NOSIGNAL) == sizeof(byte));
    wait_for(fd, POLLIN);
    return fd;
}

static short poll_events(int fd) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN | POLLOUT | POLLRDHUP};
    assert(poll(&poll_fd, 1, 0) >= 0);
    return poll_fd.revents;
}

static int socket_error(int fd) {
    int error = -1;
    socklen_t length = sizeof(error);
    assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    return error;
}

static void expect_end_of_file(int fd) {
    unsigned char byte;
    assert(recv(fd, &byte, sizeof(byte), MSG_DONTWAIT) == 0);
}

static void expect_receive_error(int fd, int error) {
    unsigned char byte;
    assert(recv(fd, &byte, sizeof(byte), MSG_DONTWAIT) == -1);
    assert(errno == error);
}

static void expect_send_error(int fd, int error) {
    unsigned char byte = 0;
    assert(send(fd, &byte, sizeof(byte), MSG_NOSIGNAL) == -1);
    assert(errno == error);
}

int main(int argc, char **argv) {
    assert(argc == 6);
    struct sockaddr_in reset = gateway_address(argv[1]);
    struct sockaddr_in unresponsive = gateway_address(argv[2]);
    struct sockaddr_in refused = gateway_address(argv[3]);
    struct sockaddr_in half_closed = gateway_address(argv[4]);
    struct sockaddr_in open = gateway_address(argv[5]);

    // A peer reset is reported once, by whichever of receive, send, or
    // SO_ERROR comes first, and leaves both directions closed.
    int fd = connect_and_reset(&reset);
    assert(poll_events(fd) == (CLOSED_EVENTS | POLLERR));
    expect_receive_error(fd, ECONNRESET);
    assert(poll_events(fd) == CLOSED_EVENTS);
    expect_end_of_file(fd);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    fd = connect_and_reset(&reset);
    expect_send_error(fd, ECONNRESET);
    expect_send_error(fd, EPIPE);
    expect_end_of_file(fd);
    assert(socket_error(fd) == 0);
    assert(poll_events(fd) == CLOSED_EVENTS);
    assert(close(fd) == 0);

    fd = connect_and_reset(&reset);
    assert(socket_error(fd) == ECONNRESET);
    assert(poll_events(fd) == CLOSED_EVENTS);
    expect_end_of_file(fd);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // Shutting down a pending connect aborts it with a reset and leaves the
    // socket unconnected.
    fd = connect_to(&unresponsive, SOCK_NONBLOCK);
    assert(poll_events(fd) == 0);
    assert(shutdown(fd, SHUT_RDWR) == 0);
    assert(poll_events(fd) == (UNCONNECTED_EVENTS | POLLERR));
    assert(socket_error(fd) == ECONNRESET);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    expect_receive_error(fd, ENOTCONN);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // A connect that fails in the background leaves both directions closed.
    fd = connect_to(&refused, SOCK_NONBLOCK);
    wait_for(fd, POLLOUT);
    assert(poll_events(fd) == (CLOSED_EVENTS | POLLERR));
    assert(socket_error(fd) == ECONNREFUSED);
    assert(poll_events(fd) == CLOSED_EVENTS);
    expect_end_of_file(fd);
    expect_send_error(fd, EPIPE);
    assert(shutdown(fd, SHUT_RDWR) == -1);
    assert(errno == ENOTCONN);
    assert(poll_events(fd) == CLOSED_EVENTS);
    assert(close(fd) == 0);

    // A connect that reports its own failure leaves the socket unconnected.
    fd = tcp_socket(0);
    assert(connect(fd, (const struct sockaddr *)&refused, sizeof(refused)) == -1);
    assert(errno == ECONNREFUSED);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    assert(socket_error(fd) == 0);
    expect_receive_error(fd, ENOTCONN);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // Shutting down the write side after the peer closed its own closes both
    // directions.
    fd = connect_to(&half_closed, 0);
    wait_for(fd, POLLIN);
    assert(poll_events(fd) == (POLLIN | POLLOUT | POLLRDHUP));
    assert(shutdown(fd, SHUT_WR) == 0);
    assert(poll_events(fd) == CLOSED_EVENTS);
    expect_end_of_file(fd);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // Local shutdowns are reported while the peer remains open.
    fd = connect_to(&open, 0);
    assert(poll_events(fd) == POLLOUT);
    assert(shutdown(fd, SHUT_RD) == 0);
    assert(poll_events(fd) == (POLLIN | POLLOUT | POLLRDHUP));
    expect_end_of_file(fd);
    assert(close(fd) == 0);

    fd = connect_to(&open, 0);
    assert(shutdown(fd, SHUT_WR) == 0);
    assert(poll_events(fd) == POLLOUT);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    fd = connect_to(&open, 0);
    assert(shutdown(fd, SHUT_RDWR) == 0);
    assert(poll_events(fd) == CLOSED_EVENTS);
    expect_end_of_file(fd);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // A listener can neither receive nor send, and shutting down its read
    // side leaves it unconnected.
    fd = tcp_socket(SOCK_NONBLOCK);
    assert(listen(fd, 1) == 0);
    assert(poll_events(fd) == 0);
    expect_receive_error(fd, ENOTCONN);
    expect_send_error(fd, EPIPE);
    assert(shutdown(fd, SHUT_RD) == 0);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    assert(close(fd) == 0);

    // A new socket is unconnected.
    fd = tcp_socket(SOCK_NONBLOCK);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    expect_receive_error(fd, ENOTCONN);
    expect_send_error(fd, EPIPE);
    assert(shutdown(fd, SHUT_RDWR) == -1);
    assert(errno == ENOTCONN);
    assert(close(fd) == 0);
    return 0;
}
