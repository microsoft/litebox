// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The host's AF_VSOCK connections to vsock port PORT, which the broker's vsock
// forwarder passes on to the guest's Unix socket listening on the abstract
// name `litebox-vsock:PORT`; vsock.host.py makes them.
//
//   vsock PORT         Listens on `@litebox-vsock:PORT`; prints `ready`; then
//                      serves, in order:
//                      - two connections at once: reads each to EOF (the
//                        host's half-close), then echoes it and closes;
//                      - CHURN connections in turn, more than the device
//                        holds at once, ending as: the host half-closes and
//                        this echoes; this writes and closes first; the host
//                        writes and closes at once;
//                      - AFTER_CLOSE connections in turn: reads a request,
//                        writes REPLY bytes and closes, while the host still
//                        sends, which must not lose the reply;
//                      - two connections in turn: reads BULK (then SLOW)
//                        bytes, writes as many, shuts down writing, and waits
//                        for the host's ACK and EOF before closing. The host
//                        reads the second slowly.

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL %s:%d: %s (errno %d: %s)\n", __FILE__, __LINE__,      \
                   #cond, errno, strerror(errno));                             \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

// As vsock.host.py's.
#define BULK (2 * 1024 * 1024)
#define SLOW (256 * 1024)
#define CHURN 40
#define AFTER_CLOSE 3
#define REQUEST "request!"
#define REPLY (64 * 1024)
#define ACK "ack"

static unsigned char pattern(size_t i) {
    return (unsigned char)(i * 7 + i / 4096);
}

// Reads `fd` to EOF into `buffer`, NUL-terminated.
static void read_to_eof(int fd, char *buffer, size_t size) {
    size_t got = 0;
    for (;;) {
        CHECK(got < size - 1);
        ssize_t n = read(fd, buffer + got, size - 1 - got);
        CHECK(n >= 0);
        if (n == 0) {
            break;
        }
        got += (size_t)n;
    }
    buffer[got] = '\0';
}

// Reads exactly `len` bytes.
static void read_exactly(int fd, unsigned char *buffer, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buffer + got, len - got);
        CHECK(n > 0);
        got += (size_t)n;
    }
}

static void write_all(int fd, const unsigned char *buffer, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buffer + done, len - done);
        CHECK(n > 0);
        done += (size_t)n;
    }
}

static int accept_host(int listener) {
    int fd = accept(listener, NULL, NULL);
    CHECK(fd >= 0);
    return fd;
}

// Two connections at once, each echoed once the host half-closes it.
static void serve_concurrent(int listener) {
    int fds[2];
    unsigned char data[2][4096];
    size_t got[2] = {0, 0};
    int open[2] = {1, 1};
    for (int i = 0; i < 2; i++) {
        fds[i] = accept_host(listener);
    }
    while (open[0] || open[1]) {
        struct pollfd polls[2];
        for (int i = 0; i < 2; i++) {
            polls[i] = (struct pollfd){.fd = open[i] ? fds[i] : -1, .events = POLLIN};
        }
        CHECK(poll(polls, 2, -1) > 0);
        for (int i = 0; i < 2; i++) {
            if (!(polls[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
                continue;
            }
            CHECK(got[i] < sizeof(data[i]));
            ssize_t n = read(fds[i], data[i] + got[i], sizeof(data[i]) - got[i]);
            CHECK(n >= 0);
            if (n == 0) {
                open[i] = 0;
            }
            got[i] += (size_t)n;
        }
    }
    for (int i = 0; i < 2; i++) {
        CHECK(got[i] > 0);
        // After the host's EOF, writes still reach it.
        write_all(fds[i], data[i], got[i]);
        CHECK(close(fds[i]) == 0);
    }
}

// One connection after another, each ending one of three ways (see the
// header).
static void serve_churn(int listener) {
    char buffer[64], expected[64];
    for (int i = 0; i < CHURN; i++) {
        int fd = accept_host(listener);
        switch (i % 3) {
        case 0:
            read_to_eof(fd, buffer, sizeof(buffer));
            snprintf(expected, sizeof(expected), "ping %d", i);
            CHECK(strcmp(buffer, expected) == 0);
            write_all(fd, (const unsigned char *)buffer, strlen(buffer));
            break;
        case 1:
            snprintf(buffer, sizeof(buffer), "hello %d", i);
            write_all(fd, (const unsigned char *)buffer, strlen(buffer));
            break;
        default:
            read_to_eof(fd, buffer, sizeof(buffer));
            snprintf(expected, sizeof(expected), "abort %d", i);
            CHECK(strcmp(buffer, expected) == 0);
            break;
        }
        CHECK(close(fd) == 0);
    }
}

// Replies to a request and closes at once, while the host still sends.
static void serve_after_close(int listener) {
    static unsigned char buffer[REPLY];
    for (int i = 0; i < AFTER_CLOSE; i++) {
        int fd = accept_host(listener);
        read_exactly(fd, buffer, strlen(REQUEST));
        CHECK(memcmp(buffer, REQUEST, strlen(REQUEST)) == 0);
        for (size_t j = 0; j < REPLY; j++) {
            buffer[j] = pattern(j);
        }
        write_all(fd, buffer, REPLY);
        CHECK(close(fd) == 0);
    }
}

// `size` bytes each way, through the device's and the sockets' flow control.
static void serve_bulk(int listener, size_t size) {
    static unsigned char buffer[64 * 1024];
    int fd = accept_host(listener);
    for (size_t done = 0; done < size;) {
        size_t len = size - done < sizeof(buffer) ? size - done : sizeof(buffer);
        ssize_t n = read(fd, buffer, len);
        CHECK(n > 0);
        for (ssize_t i = 0; i < n; i++) {
            CHECK(buffer[i] == pattern(done + (size_t)i));
        }
        done += (size_t)n;
    }
    for (size_t done = 0; done < size; done += sizeof(buffer)) {
        size_t len = size - done < sizeof(buffer) ? size - done : sizeof(buffer);
        for (size_t i = 0; i < len; i++) {
            buffer[i] = pattern(done + i);
        }
        write_all(fd, buffer, len);
    }
    CHECK(shutdown(fd, SHUT_WR) == 0);
    // The host acknowledges once it has read everything, then ends.
    char ack[sizeof(ACK) + 1];
    read_to_eof(fd, ack, sizeof(ack));
    CHECK(strcmp(ack, ACK) == 0);
    CHECK(close(fd) == 0);
}

static int serve(const char *port) {
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    // Abstract: a NUL, then the name, which the address length bounds.
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int name = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                        "litebox-vsock:%s", port);
    CHECK(name > 0 && (size_t)name < sizeof(address.sun_path) - 1);
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + (size_t)name);
    CHECK(bind(listener, (struct sockaddr *)&address, len) == 0);
    CHECK(listen(listener, 8) == 0);
    printf("ready\n");
    fflush(stdout);
    serve_concurrent(listener);
    serve_churn(listener);
    serve_after_close(listener);
    serve_bulk(listener, BULK);
    serve_bulk(listener, SLOW);
    CHECK(close(listener) == 0);
    printf("served\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: vsock PORT\n");
        return 2;
    }
    return serve(argv[1]);
}
