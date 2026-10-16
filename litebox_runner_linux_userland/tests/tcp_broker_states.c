// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks how TCP sockets that are not, or are no longer, connected report
// readiness, receives, sends, connects, and pending errors.

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

static void expect_connect_error(int fd, const struct sockaddr_in *address, int error) {
    assert(connect(fd, (const struct sockaddr *)address, sizeof(*address)) == -1);
    assert(errno == error);
}

static void expect_shutdown_not_connected(int fd, int how) {
    assert(shutdown(fd, how) == -1);
    assert(errno == ENOTCONN);
}

// Waits for `length` bytes to be queued on a socket whose read side is shut
// down, which makes it readable whether or not data is queued.
static void wait_for_queued(int fd, ssize_t length) {
    unsigned char buffer[8];
    for (int attempt = 0; attempt < 500; attempt++) {
        ssize_t queued = recv(fd, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT);
        assert(queued >= 0);
        if (queued >= length) {
            return;
        }
        assert(usleep(10000) == 0);
    }
    abort();
}

// Sends without waiting until a pending connect completes, which the socket
// must notice without being polled.
static void expect_send_error_once_connected(int fd, int error) {
    unsigned char byte = 0;
    for (int attempt = 0; attempt < 500; attempt++) {
        assert(send(fd, &byte, sizeof(byte), MSG_NOSIGNAL | MSG_DONTWAIT) == -1);
        if (errno != EAGAIN) {
            assert(errno == error);
            return;
        }
        assert(usleep(10000) == 0);
    }
    abort();
}

int main(int argc, char **argv) {
    assert(argc == 7);
    struct sockaddr_in reset = gateway_address(argv[1]);
    struct sockaddr_in unresponsive = gateway_address(argv[2]);
    struct sockaddr_in refused = gateway_address(argv[3]);
    struct sockaddr_in half_closed = gateway_address(argv[4]);
    struct sockaddr_in open = gateway_address(argv[5]);
    // The peer sends two bytes and keeps the connection open.
    struct sockaddr_in greeting = gateway_address(argv[6]);
    struct sockaddr_in zero_port = gateway_address("0");

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

    // An aborted connect's reset is also reported once, by whichever of
    // receive or send comes first.
    fd = connect_to(&unresponsive, SOCK_NONBLOCK);
    assert(shutdown(fd, SHUT_RDWR) == 0);
    expect_receive_error(fd, ECONNRESET);
    expect_receive_error(fd, ENOTCONN);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    expect_send_error(fd, EPIPE);
    assert(socket_error(fd) == 0);
    assert(close(fd) == 0);

    fd = connect_to(&unresponsive, SOCK_NONBLOCK);
    assert(shutdown(fd, SHUT_RDWR) == 0);
    expect_send_error(fd, ECONNRESET);
    expect_send_error(fd, EPIPE);
    expect_receive_error(fd, ENOTCONN);
    assert(socket_error(fd) == 0);
    assert(close(fd) == 0);

    // A connect while another is pending reports that one is already in
    // progress, whatever its address.
    fd = connect_to(&unresponsive, SOCK_NONBLOCK);
    expect_connect_error(fd, &unresponsive, EALREADY);
    expect_connect_error(fd, &zero_port, EALREADY);
    assert(poll_events(fd) == 0);
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

    // Its failure is reported once, by whichever of connect or SO_ERROR comes
    // first, which leaves a later connect only an abort to report.
    fd = connect_to(&refused, SOCK_NONBLOCK);
    wait_for(fd, POLLOUT);
    assert(connect(fd, (const struct sockaddr *)&refused, sizeof(refused)) == -1);
    assert(errno == ECONNREFUSED);
    assert(socket_error(fd) == 0);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    assert(close(fd) == 0);

    fd = connect_to(&refused, SOCK_NONBLOCK);
    wait_for(fd, POLLOUT);
    assert(socket_error(fd) == ECONNREFUSED);
    assert(connect(fd, (const struct sockaddr *)&refused, sizeof(refused)) == -1);
    assert(errno == ECONNABORTED);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    assert(close(fd) == 0);

    // A connect that reports its own failure leaves the socket unconnected,
    // discarding any shutdown.
    fd = tcp_socket(0);
    expect_shutdown_not_connected(fd, SHUT_RD);
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

    // A connected socket rejects further connects, whatever their address,
    // including when only a shutdown observed that it connected.
    fd = connect_to(&open, SOCK_NONBLOCK);
    wait_for(fd, POLLOUT);
    assert(connect(fd, (const struct sockaddr *)&open, sizeof(open)) == 0);
    expect_connect_error(fd, &open, EISCONN);
    expect_connect_error(fd, &zero_port, EISCONN);
    assert(close(fd) == 0);

    fd = connect_to(&open, SOCK_NONBLOCK);
    wait_for(fd, POLLOUT);
    assert(shutdown(fd, SHUT_WR) == 0);
    expect_connect_error(fd, &open, EISCONN);
    assert(close(fd) == 0);

    // A shutdown of a socket that is not connected fails but still takes
    // effect, and persists once the socket connects.
    fd = tcp_socket(0);
    expect_shutdown_not_connected(fd, SHUT_RD);
    assert(poll_events(fd) == CLOSED_EVENTS);
    expect_end_of_file(fd);
    expect_send_error(fd, EPIPE);
    assert(connect(fd, (const struct sockaddr *)&open, sizeof(open)) == 0);
    assert(poll_events(fd) == (POLLIN | POLLOUT | POLLRDHUP));
    expect_end_of_file(fd);
    expect_connect_error(fd, &open, EISCONN);
    assert(close(fd) == 0);

    fd = tcp_socket(0);
    expect_shutdown_not_connected(fd, SHUT_WR);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    expect_receive_error(fd, ENOTCONN);
    expect_send_error(fd, EPIPE);
    assert(connect(fd, (const struct sockaddr *)&open, sizeof(open)) == 0);
    assert(poll_events(fd) == POLLOUT);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // A send waits for a pending connect, and reports its failure, before
    // reporting the shutdown.
    fd = tcp_socket(SOCK_NONBLOCK);
    expect_shutdown_not_connected(fd, SHUT_WR);
    expect_connect_error(fd, &unresponsive, EINPROGRESS);
    assert(poll_events(fd) == 0);
    expect_send_error(fd, EAGAIN);
    assert(close(fd) == 0);

    fd = tcp_socket(SOCK_NONBLOCK);
    expect_shutdown_not_connected(fd, SHUT_WR);
    expect_connect_error(fd, &open, EINPROGRESS);
    expect_send_error_once_connected(fd, EPIPE);
    assert(close(fd) == 0);

    fd = tcp_socket(SOCK_NONBLOCK);
    expect_shutdown_not_connected(fd, SHUT_WR);
    expect_connect_error(fd, &refused, EINPROGRESS);
    expect_send_error_once_connected(fd, ECONNREFUSED);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // Receives still return queued data, without waiting for more.
    fd = tcp_socket(0);
    expect_shutdown_not_connected(fd, SHUT_RD);
    assert(connect(fd, (const struct sockaddr *)&greeting, sizeof(greeting)) == 0);
    wait_for_queued(fd, 2);
    unsigned char buffer[4];
    assert(recv(fd, buffer, sizeof(buffer), MSG_PEEK | MSG_WAITALL) == 2);
    assert(recv(fd, buffer, sizeof(buffer), MSG_WAITALL) == 2);
    expect_end_of_file(fd);
    assert(close(fd) == 0);

    // Both directions are closed once the peer closes its own.
    fd = tcp_socket(0);
    expect_shutdown_not_connected(fd, SHUT_WR);
    assert(connect(fd, (const struct sockaddr *)&half_closed, sizeof(half_closed)) == 0);
    wait_for(fd, POLLRDHUP);
    assert(poll_events(fd) == CLOSED_EVENTS);
    expect_end_of_file(fd);
    expect_send_error(fd, EPIPE);
    assert(close(fd) == 0);

    // A listener ignores a shutdown recorded before it listened and can neither
    // receive nor send, and shutting down its read side leaves it unconnected,
    // discarding the shutdown.
    fd = tcp_socket(SOCK_NONBLOCK);
    expect_shutdown_not_connected(fd, SHUT_RD);
    assert(listen(fd, 1) == 0);
    assert(poll_events(fd) == 0);
    expect_receive_error(fd, ENOTCONN);
    expect_send_error(fd, EPIPE);
    expect_connect_error(fd, &open, EISCONN);
    assert(shutdown(fd, SHUT_RD) == 0);
    assert(poll_events(fd) == UNCONNECTED_EVENTS);
    expect_receive_error(fd, ENOTCONN);
    assert(close(fd) == 0);
    return 0;
}
