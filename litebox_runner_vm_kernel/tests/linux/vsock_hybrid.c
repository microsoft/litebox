// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// AF_VSOCK connections between the guest and vsock_hybrid.host.py over hybrid vsock (host Unix
// sockets), which has no half-close: fixed-size messages and full closes only. Listens, prints
// `ready`, serves the host's connections in order (see main()), then connects to the host's
// ports, and prints `vsock-hybrid ok`.

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL %s:%d: %s (errno %d: %s)\n", __FILE__, __LINE__, #cond, errno,             \
                   strerror(errno));                                                               \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

// As vsock_hybrid.host.py's.
#define PORT 1024
#define SIGNAL_PORT 1025
#define HOST_ECHO_PORT 2000
#define HOST_REFUSING_PORT 2001
#define MESSAGE 64
#define CONCURRENT 4
#define BULK (1024 * 1024)
#define SHUT "shut"

static unsigned char pattern(size_t i) {
    return (unsigned char)(i * 7 + i / 4096);
}

static void read_exactly(int fd, unsigned char *buffer, size_t len) {
    for (size_t got = 0; got < len;) {
        ssize_t n = read(fd, buffer + got, len - got);
        CHECK(n > 0);
        got += (size_t)n;
    }
}

static void write_all(int fd, const unsigned char *buffer, size_t len) {
    for (size_t done = 0; done < len;) {
        ssize_t n = write(fd, buffer + done, len - done);
        CHECK(n > 0);
        done += (size_t)n;
    }
}

static void check_pattern(const unsigned char *buffer, size_t len, size_t offset) {
    for (size_t i = 0; i < len; i++) {
        CHECK(buffer[i] == pattern(offset + i));
    }
}

static void fill_pattern(unsigned char *buffer, size_t len, size_t offset) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = pattern(offset + i);
    }
}

// Waits for the host's close.
static void read_eof(int fd) {
    unsigned char byte;
    CHECK(read(fd, &byte, 1) == 0);
}

static int listen_on(unsigned int port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_vm address = {
        .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_ANY, .svm_port = port};
    CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(listen(fd, 8) == 0);
    return fd;
}

static int accept_host(int listener) {
    struct sockaddr_vm peer = {0};
    socklen_t len = sizeof(peer);
    int fd = accept(listener, (struct sockaddr *)&peer, &len);
    CHECK(fd >= 0);
    CHECK(len == sizeof(peer) && peer.svm_family == AF_VSOCK && peer.svm_cid == VMADDR_CID_HOST);
    return fd;
}

// Echoes a message, then waits for the host's close.
static void serve_echo(int listener) {
    unsigned char buffer[MESSAGE];
    int fd = accept_host(listener);
    read_exactly(fd, buffer, MESSAGE);
    write_all(fd, buffer, MESSAGE);
    read_eof(fd);
    CHECK(close(fd) == 0);
}

// CONCURRENT connections at once, each echoed once its message is complete.
static void serve_concurrent(int listener) {
    int fds[CONCURRENT];
    unsigned char data[CONCURRENT][MESSAGE];
    size_t got[CONCURRENT] = {0};
    int pending = CONCURRENT;
    for (int i = 0; i < CONCURRENT; i++) {
        fds[i] = accept_host(listener);
    }
    while (pending > 0) {
        struct pollfd polls[CONCURRENT];
        for (int i = 0; i < CONCURRENT; i++) {
            polls[i] = (struct pollfd){.fd = got[i] < MESSAGE ? fds[i] : -1, .events = POLLIN};
        }
        CHECK(poll(polls, CONCURRENT, -1) > 0);
        for (int i = 0; i < CONCURRENT; i++) {
            if (!polls[i].revents) {
                continue;
            }
            ssize_t n = read(fds[i], data[i] + got[i], MESSAGE - got[i]);
            CHECK(n > 0);
            got[i] += (size_t)n;
            if (got[i] == MESSAGE) {
                write_all(fds[i], data[i], MESSAGE);
                pending--;
            }
        }
    }
    for (int i = 0; i < CONCURRENT; i++) {
        read_eof(fds[i]);
        CHECK(close(fds[i]) == 0);
    }
}

// BULK bytes each way, in turn; the host reads slowly.
static void serve_bulk(int listener) {
    static unsigned char buffer[64 * 1024];
    int fd = accept_host(listener);
    for (size_t done = 0; done < BULK;) {
        size_t len = BULK - done < sizeof(buffer) ? BULK - done : sizeof(buffer);
        ssize_t n = read(fd, buffer, len);
        CHECK(n > 0);
        check_pattern(buffer, (size_t)n, done);
        done += (size_t)n;
    }
    for (size_t done = 0; done < BULK; done += sizeof(buffer)) {
        fill_pattern(buffer, sizeof(buffer), done);
        write_all(fd, buffer, sizeof(buffer));
    }
    read_eof(fd);
    CHECK(close(fd) == 0);
}

// The host sends a message and closes: this reads it, then EOF, and a send
// fails with EPIPE.
static void serve_host_close(int listener) {
    unsigned char buffer[MESSAGE];
    int fd = accept_host(listener);
    read_exactly(fd, buffer, MESSAGE);
    check_pattern(buffer, MESSAGE, 0);
    read_eof(fd);
    errno = 0;
    CHECK(send(fd, "x", 1, MSG_NOSIGNAL) < 0 && errno == EPIPE);
    CHECK(close(fd) == 0);
}

// Replies and closes with the host's message unread, which must not reset
// the host's end.
static void serve_guest_close(int listener) {
    unsigned char buffer[MESSAGE];
    int fd = accept_host(listener);
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    CHECK(poll(&poll_fd, 1, -1) == 1 && poll_fd.revents == POLLIN);
    fill_pattern(buffer, MESSAGE, 0);
    write_all(fd, buffer, MESSAGE);
    CHECK(close(fd) == 0);
}

// After this end's SHUT_WR, signalled on a second connection, the host still
// sends, and sees EOF only at the close.
static void serve_shutdown(int listener, int signal_listener) {
    unsigned char buffer[MESSAGE];
    int fd = accept_host(listener);
    int signal_fd = accept_host(signal_listener);
    fill_pattern(buffer, MESSAGE, 0);
    write_all(fd, buffer, MESSAGE);
    CHECK(shutdown(fd, SHUT_WR) == 0);
    write_all(signal_fd, (const unsigned char *)SHUT, strlen(SHUT));
    read_exactly(fd, buffer, MESSAGE);
    check_pattern(buffer, MESSAGE, MESSAGE);
    CHECK(close(fd) == 0);
    read_eof(signal_fd);
    CHECK(close(signal_fd) == 0);
}

static int so_error(int fd) {
    int error = -1;
    socklen_t len = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && len == sizeof(error));
    return error;
}

// The host echoes a message on its listening port and closes; a connect to
// the other is reset (ECONNRESET, left pending), as by Firecracker, or times
// out (ETIMEDOUT) under vhost-device-vsock 0.3.0, which never answers it.
static void connect_host_ports(void) {
    unsigned char buffer[MESSAGE];
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_vm address = {
        .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = HOST_ECHO_PORT};
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    fill_pattern(buffer, MESSAGE, 2 * MESSAGE);
    write_all(fd, buffer, MESSAGE);
    read_exactly(fd, buffer, MESSAGE);
    check_pattern(buffer, MESSAGE, 2 * MESSAGE);
    read_eof(fd);
    CHECK(close(fd) == 0);

    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    address.svm_port = HOST_REFUSING_PORT;
    errno = 0;
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0);
    int error = errno;
    CHECK(error == ECONNRESET || error == ETIMEDOUT);
    CHECK(error != ECONNRESET || so_error(fd) == ECONNRESET);
    CHECK(so_error(fd) == 0);
    CHECK(close(fd) == 0);
}

int main(void) {
    int listener = listen_on(PORT);
    int signal_listener = listen_on(SIGNAL_PORT);
    printf("ready\n");
    fflush(stdout);
    serve_echo(listener);
    serve_concurrent(listener);
    serve_bulk(listener);
    serve_host_close(listener);
    serve_guest_close(listener);
    serve_shutdown(listener, signal_listener);
    CHECK(close(listener) == 0);
    CHECK(close(signal_listener) == 0);
    connect_host_ports();
    printf("vsock-hybrid ok\n");
    return 0;
}
