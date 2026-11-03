// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// AF_VSOCK connections between the guest and vsock.host.py, on the VM's
// virtio-vsock device.
//
//   vsock PORT   Listens on PORT, PORT + 3 and PORT + 4, prints `ready`, and
//                serves the host's connections in order (see serve()):
//                concurrent ones, more in turn than the device holds, closes
//                racing the host's sends, bulk transfers, a local SHUT_RD,
//                and tokio-vsock's nonblocking edge-triggered I/O; prints
//                `served`. Then connects to the two host ports read from
//                PORT + 4 (one echoing, one refusing): blocking, nonblocking
//                with epoll, bulk with EPIPE/SIGPIPE, and concurrently; the
//                host checks each connection's name and port. Prints
//                `connected`.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

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
#define REPLIED "replied"
#define FIRST (128 * 1024)
#define GO "go"
#define LATER "later"
#define BACKPRESSURE (1024 * 1024)
#define ACCEPT4 "accept4"
#define CLIENT_BULK (1024 * 1024)
// More than a socket queues, so a send of it is partial.
#define SEND_CHUNK (256 * 1024)

static unsigned char pattern(size_t i) {
    return (unsigned char)(i * 7 + i / 4096);
}

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

// Accepts a connection, checking its peer address names the host.
static int accept_host(int listener) {
    struct sockaddr_vm peer = {0};
    socklen_t len = sizeof(peer);
    int fd = accept(listener, (struct sockaddr *)&peer, &len);
    CHECK(fd >= 0);
    CHECK(len == sizeof(peer) && peer.svm_family == AF_VSOCK && peer.svm_cid == VMADDR_CID_HOST);
    struct sockaddr_vm name = {0};
    len = sizeof(name);
    CHECK(getpeername(fd, (struct sockaddr *)&name, &len) == 0);
    CHECK(len == sizeof(name) && memcmp(&name, &peer, sizeof(peer)) == 0);
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

// Connections in turn, more than the device holds, ending in three ways:
// the host half-closes and this echoes; this writes and closes first; the
// host writes and closes at once.
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

// Replies to a request and closes at once, while the host still sends, which
// must not lose the reply.
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

// `size` bytes each way, then waits for the host's ACK and EOF.
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
    char ack[sizeof(ACK) + 1];
    read_to_eof(fd, ack, sizeof(ack));
    CHECK(strcmp(ack, ACK) == 0);
    CHECK(close(fd) == 0);
}

// A page receives cannot write into.
static void *unwritable(void) {
    static void *page;
    if (!page) {
        page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(page != MAP_FAILED);
    }
    return page;
}

// After SHUT_RD, as in Linux: receives report EOF, dropping queued data, the
// peer has no name, a send to an address fails with EISCONN and a connect
// with EINVAL, but writes still reach the host.
static void serve_local_shutdown(int listener) {
    char buffer[16];
    int fd = accept_host(listener);
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    CHECK(poll(&poll_fd, 1, -1) == 1 && poll_fd.revents == POLLIN);
    CHECK(shutdown(fd, SHUT_RD) == 0);
    CHECK(recv(fd, unwritable(), 1, 0) == 0);
    CHECK(recv(fd, buffer, sizeof(buffer), 0) == 0);
    struct sockaddr_vm name = {0};
    socklen_t len = sizeof(name);
    CHECK(getpeername(fd, (struct sockaddr *)&name, &len) < 0 && errno == ENOTCONN);
    struct sockaddr_vm host = {.svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST,
                               .svm_port = 1024};
    CHECK(sendto(fd, "x", 1, MSG_NOSIGNAL, (struct sockaddr *)&host,
                 sizeof(host)) < 0 && errno == EISCONN);
    CHECK(connect(fd, (struct sockaddr *)&host, sizeof(host)) < 0 &&
          errno == EINVAL);
    write_all(fd, (const unsigned char *)REPLIED, strlen(REPLIED));
    CHECK(close(fd) == 0);
}

static void set_nonblocking(int fd) {
    int on = 1;
    CHECK(ioctl(fd, FIONBIO, &on) == 0);
    CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK);
}

// Watches `fd` with edge-triggered epoll, as Tokio's reactor does.
static void watch(int epfd, int fd) {
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.fd = fd};
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) == 0);
}

// Waits for the next edge, once an operation found its descriptor not ready.
static void wait_edge(int epfd) {
    CHECK(errno == EAGAIN);
    struct epoll_event events[4];
    CHECK(epoll_wait(epfd, events, 4, -1) > 0);
}

// Accepts on the nonblocking `listener`, with `accept4` if `flags` is
// nonzero.
static int accept_edge_triggered(int epfd, int listener, void *peer, socklen_t capacity,
                                 socklen_t *len, int flags) {
    for (;;) {
        *len = capacity;
        struct sockaddr *address = peer;
        int fd = flags ? accept4(listener, address, len, flags) : accept(listener, address, len);
        if (fd >= 0) {
            return fd;
        }
        wait_edge(epfd);
    }
}

// Reads up to `size` bytes, or to EOF, draining `fd` before each wait.
static size_t read_edge_triggered(int epfd, int fd, unsigned char *buffer, size_t size) {
    size_t got = 0;
    while (got < size) {
        ssize_t n = read(fd, buffer + got, size - got);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            wait_edge(epfd);
            continue;
        }
        got += (size_t)n;
    }
    return got;
}

// Sends `len` bytes, `chunk` at a time, counting partial and full sends.
static void send_edge_triggered(int epfd, int fd, const unsigned char *buffer, size_t len,
                                size_t chunk, int *partial, int *full) {
    for (size_t done = 0; done < len;) {
        size_t want = len - done < chunk ? len - done : chunk;
        ssize_t n = send(fd, buffer + done, want, MSG_NOSIGNAL);
        if (n < 0) {
            ++*full;
            wait_edge(epfd);
            continue;
        }
        CHECK(n > 0);
        if ((size_t)n < want) {
            ++*partial;
        }
        done += (size_t)n;
    }
}

// As tokio-vsock 0.7 (vsock 0.5): FIONBIO and edge-triggered epoll. One
// connection by `accept`, with partial and EAGAIN sends as the host reads
// slowly; one by `accept4` with a short address buffer.
static void serve_nonblocking(int listener) {
    static unsigned char buffer[BACKPRESSURE];
    int partial = 0, full = 0;
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epfd >= 0);
    watch(epfd, listener);

    struct sockaddr_vm peer = {0};
    socklen_t len;
    int fd = accept_edge_triggered(epfd, listener, &peer, sizeof(peer), &len, 0);
    CHECK(len == sizeof(peer) && peer.svm_family == AF_VSOCK && peer.svm_cid == VMADDR_CID_HOST);
    // Nothing else is queued until this connection ends.
    CHECK(accept(listener, NULL, NULL) < 0 && errno == EAGAIN);
    CHECK(!(fcntl(fd, F_GETFL) & O_NONBLOCK) && !(fcntl(fd, F_GETFD) & FD_CLOEXEC));
    set_nonblocking(fd);
    watch(epfd, fd);
    CHECK(read_edge_triggered(epfd, fd, buffer, FIRST) == FIRST);
    for (size_t i = 0; i < FIRST; i++) {
        CHECK(buffer[i] == pattern(i));
    }
    // The host sends LATER only once it reads GO.
    CHECK(read(fd, buffer, 1) < 0 && errno == EAGAIN);
    send_edge_triggered(epfd, fd, (const unsigned char *)GO, strlen(GO), SEND_CHUNK, &partial,
                        &full);
    CHECK(read_edge_triggered(epfd, fd, buffer, strlen(LATER)) == strlen(LATER));
    CHECK(memcmp(buffer, LATER, strlen(LATER)) == 0);
    for (size_t i = 0; i < BACKPRESSURE; i++) {
        buffer[i] = pattern(i);
    }
    partial = full = 0;
    send_edge_triggered(epfd, fd, buffer, BACKPRESSURE, SEND_CHUNK, &partial, &full);
    CHECK(partial > 0 && full > 0);
    CHECK(read_edge_triggered(epfd, fd, buffer, sizeof(buffer)) == strlen(ACK));
    CHECK(memcmp(buffer, ACK, strlen(ACK)) == 0);
    CHECK(close(fd) == 0);

    // A short address buffer gets the start of the address and its full length.
    unsigned char address[sizeof(struct sockaddr_vm)];
    memset(address, 0xff, sizeof(address));
    fd = accept_edge_triggered(epfd, listener, address, 4, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    sa_family_t family;
    memcpy(&family, address, sizeof(family));
    CHECK(len == sizeof(struct sockaddr_vm) && family == AF_VSOCK && address[4] == 0xff);
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    watch(epfd, fd);
    size_t got = read_edge_triggered(epfd, fd, buffer, sizeof(buffer));
    CHECK(got == strlen(ACCEPT4) && memcmp(buffer, ACCEPT4, got) == 0);
    send_edge_triggered(epfd, fd, buffer, got, SEND_CHUNK, &partial, &full);
    CHECK(close(fd) == 0);
    CHECK(close(epfd) == 0);
}

static int so_error(int fd) {
    int error = -1;
    socklen_t len = sizeof(error);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && len == sizeof(error));
    return error;
}

static struct sockaddr_vm host_address(unsigned int port) {
    return (struct sockaddr_vm){
        .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = port};
}

static void read_host_ports(int listener, unsigned int *echo, unsigned int *refused) {
    char buffer[64];
    int fd = accept_host(listener);
    read_to_eof(fd, buffer, sizeof(buffer));
    CHECK(sscanf(buffer, "%u %u", echo, refused) == 2);
    CHECK(close(fd) == 0);
}

// Checks the names of `fd`, connected to the host's `port`, and returns its
// own port; as in Linux, its connect bound it to VMADDR_CID_ANY.
static unsigned int check_names(int fd, unsigned int port) {
    struct sockaddr_vm name = {0};
    socklen_t len = sizeof(name);
    CHECK(getsockname(fd, (struct sockaddr *)&name, &len) == 0);
    CHECK(len == sizeof(name) && name.svm_family == AF_VSOCK &&
          name.svm_cid == VMADDR_CID_ANY && name.svm_port > 1023 &&
          name.svm_port != VMADDR_PORT_ANY);
    struct sockaddr_vm peer = {0};
    len = sizeof(peer);
    CHECK(getpeername(fd, (struct sockaddr *)&peer, &len) == 0);
    CHECK(len == sizeof(peer) && peer.svm_family == AF_VSOCK &&
          peer.svm_cid == VMADDR_CID_HOST && peer.svm_port == port);
    return name.svm_port;
}

static unsigned int connect_host(int fd, unsigned int port) {
    struct sockaddr_vm address = host_address(port);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    return check_names(fd, port);
}

// Writes `NAME PORT` to `fd` and half-closes it.
static void send_name(int fd, const char *name, unsigned int port, char *message, size_t size) {
    int len = snprintf(message, size, "%s %u", name, port);
    CHECK(len > 0 && (size_t)len < size);
    write_all(fd, (const unsigned char *)message, (size_t)len);
    CHECK(shutdown(fd, SHUT_WR) == 0);
}

static void echo_with_host(int fd, const char *name, unsigned int port) {
    char message[64], echo[64];
    send_name(fd, name, port, message, sizeof(message));
    read_to_eof(fd, echo, sizeof(echo));
    CHECK(strcmp(echo, message) == 0);
    CHECK(close(fd) == 0);
}

// Receives into memory they cannot write check the socket first, as on Linux:
// ENOTCONN, EAGAIN, and EFAULT only once data waits, which stays. A read of
// nothing reads nothing, without checking the socket.
// A refused blocking connect leaves its error pending, as on Linux: poll
// reports it, a connect to another family fails with EINVAL without taking
// it, and SO_ERROR takes it; the socket stays bound and connects again.
static void connect_blocking(unsigned int echo, unsigned int refused) {
    char message[64], reply[64];
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    CHECK(read(fd, reply, 0) == 0);
    CHECK(recv(fd, reply, 0, 0) < 0 && errno == ENOTCONN);
    CHECK(recv(fd, unwritable(), 1, 0) < 0 && errno == ENOTCONN);
    unsigned int port = connect_host(fd, echo);
    CHECK(recv(fd, unwritable(), 1, MSG_DONTWAIT) < 0 && errno == EAGAIN);
    send_name(fd, "blocking", port, message, sizeof(message));
    struct pollfd readable = {.fd = fd, .events = POLLIN};
    CHECK(poll(&readable, 1, -1) == 1);
    CHECK(recv(fd, unwritable(), 1, 0) < 0 && errno == EFAULT);
    struct iovec iov = {.iov_base = unwritable(), .iov_len = 1};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    CHECK(recvmsg(fd, &msg, 0) < 0 && errno == EFAULT);
    read_to_eof(fd, reply, sizeof(reply));
    CHECK(strcmp(reply, message) == 0);
    CHECK(close(fd) == 0);

    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_vm address = host_address(refused);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 && errno == ECONNRESET);
    // Unconnected, not shut down: writable, and not hung up.
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN | POLLOUT};
    CHECK(poll(&poll_fd, 1, 0) == 1 && poll_fd.revents == (POLLOUT | POLLERR));
    struct sockaddr_un unix_address = {.sun_family = AF_UNIX, .sun_path = "/vsock"};
    CHECK(connect(fd, (struct sockaddr *)&unix_address, sizeof(unix_address)) < 0 &&
          errno == EINVAL);
    CHECK(so_error(fd) == ECONNRESET);
    CHECK(so_error(fd) == 0);
    CHECK(poll(&poll_fd, 1, 0) == 1 && poll_fd.revents == POLLOUT);
    struct sockaddr_vm name = {0};
    socklen_t len = sizeof(name);
    CHECK(getpeername(fd, (struct sockaddr *)&name, &len) < 0 && errno == ENOTCONN);
    len = sizeof(name);
    CHECK(getsockname(fd, (struct sockaddr *)&name, &len) == 0);
    CHECK(name.svm_port != VMADDR_PORT_ANY);
    port = connect_host(fd, echo);
    CHECK(port == name.svm_port);
    echo_with_host(fd, "retry", port);
}

// On a connected socket, as in Linux, a connect, and a send to an address,
// fail with EISCONN, before the address is checked.
static void check_connected_addresses(int fd) {
    struct sockaddr_vm bad_flags = host_address(1024), vsock = host_address(1024);
    bad_flags.svm_flags = 2;
    struct sockaddr_in inet = {.sin_family = AF_INET};
    struct sockaddr_in6 inet6 = {.sin6_family = AF_INET6};
    const struct {
        int send;
        const void *address;
        socklen_t len;
    } cases[] = {
        {0, &bad_flags, sizeof(bad_flags)}, {0, &vsock, sizeof(vsock) - 1},
        {0, &inet, sizeof(inet)},           {1, &vsock, sizeof(vsock) - 1},
        {1, &inet6, sizeof(inet6)},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const struct sockaddr *address = cases[i].address;
        errno = 0;
        long result = cases[i].send ? sendto(fd, "x", 1, MSG_NOSIGNAL, address, cases[i].len)
                                    : connect(fd, address, cases[i].len);
        CHECK(result == -1 && errno == EISCONN);
    }
}

// As tokio-vsock 0.7's `VsockStream::connect`: EINPROGRESS, then EPOLLOUT
// and SO_ERROR 0. A refused connect is POLLOUT | POLLERR (not hung up, as on
// Linux) until SO_ERROR takes the error, and the socket connects again.
static void connect_nonblocking(unsigned int echo, unsigned int refused) {
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epfd >= 0);
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct sockaddr_vm address = host_address(echo);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 && errno == EINPROGRESS);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 &&
          (errno == EALREADY || errno == EISCONN));
    watch(epfd, fd);
    struct epoll_event event = {0};
    do {
        CHECK(epoll_wait(epfd, &event, 1, -1) == 1);
    } while (!(event.events & EPOLLOUT));
    CHECK(!(event.events & (EPOLLERR | EPOLLHUP)));
    CHECK(so_error(fd) == 0);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 && errno == EISCONN);
    check_connected_addresses(fd);
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN | POLLOUT};
    CHECK(poll(&poll_fd, 1, 0) == 1 && poll_fd.revents == POLLOUT);
    unsigned int port = check_names(fd, echo);
    char message[64];
    int len = snprintf(message, sizeof(message), "nonblocking %u", port);
    CHECK(len > 0 && (size_t)len < sizeof(message));
    int partial = 0, full = 0;
    send_edge_triggered(epfd, fd, (const unsigned char *)message, (size_t)len, SEND_CHUNK,
                        &partial, &full);
    CHECK(shutdown(fd, SHUT_WR) == 0);
    unsigned char reply[64];
    size_t got = read_edge_triggered(epfd, fd, reply, sizeof(reply));
    CHECK(got == (size_t)len && memcmp(reply, message, got) == 0);
    CHECK(close(fd) == 0);

    fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    address = host_address(refused);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 && errno == EINPROGRESS);
    poll_fd = (struct pollfd){.fd = fd, .events = POLLIN | POLLOUT};
    CHECK(poll(&poll_fd, 1, -1) == 1 && poll_fd.revents == (POLLOUT | POLLERR));
    int level_epfd = epoll_create1(EPOLL_CLOEXEC);
    CHECK(level_epfd >= 0);
    event = (struct epoll_event){.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP, .data.fd = fd};
    CHECK(epoll_ctl(level_epfd, EPOLL_CTL_ADD, fd, &event) == 0);
    CHECK(epoll_wait(level_epfd, &event, 1, 0) == 1 && event.events == (EPOLLOUT | EPOLLERR));
    CHECK(so_error(fd) == ECONNRESET);
    CHECK(so_error(fd) == 0);
    CHECK(poll(&poll_fd, 1, 0) == 1 && poll_fd.revents == POLLOUT);
    CHECK(epoll_wait(level_epfd, &event, 1, 0) == 1 && event.events == EPOLLOUT);
    address = host_address(echo);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 && errno == EINPROGRESS);
    CHECK(epoll_wait(level_epfd, &event, 1, -1) == 1 && event.events == EPOLLOUT);
    CHECK(so_error(fd) == 0);
    port = check_names(fd, echo);
    CHECK(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK) == 0);
    echo_with_host(fd, "nonblocking-retry", port);
    CHECK(close(level_epfd) == 0);
    CHECK(close(epfd) == 0);
}

static volatile sig_atomic_t sigpipes;

static void count_sigpipe(int signal) {
    (void)signal;
    sigpipes++;
}

// After SHUT_WR, a send fails with EPIPE and raises SIGPIPE unless
// MSG_NOSIGNAL, as in Linux.
static void check_epipe(int fd) {
    struct sigaction action = {.sa_handler = count_sigpipe}, old;
    CHECK(sigaction(SIGPIPE, &action, &old) == 0);
    sigpipes = 0;
    CHECK(send(fd, "x", 1, 0) < 0 && errno == EPIPE);
    CHECK(sigpipes == 1);
    CHECK(send(fd, "x", 1, MSG_NOSIGNAL) < 0 && errno == EPIPE);
    CHECK(sigpipes == 1);
    CHECK(sigaction(SIGPIPE, &old, NULL) == 0);
}

// CLIENT_BULK bytes each way, with sends after the half-close failing.
static void connect_bulk(unsigned int echo) {
    static unsigned char buffer[64 * 1024];
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    connect_host(fd, echo);
    for (size_t done = 0; done < CLIENT_BULK; done += sizeof(buffer)) {
        for (size_t i = 0; i < sizeof(buffer); i++) {
            buffer[i] = pattern(done + i);
        }
        write_all(fd, buffer, sizeof(buffer));
    }
    CHECK(shutdown(fd, SHUT_WR) == 0);
    check_epipe(fd);
    size_t done = 0;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        CHECK(n >= 0);
        if (n == 0) {
            break;
        }
        for (ssize_t i = 0; i < n; i++) {
            CHECK(buffer[i] == pattern(done + (size_t)i));
        }
        done += (size_t)n;
    }
    CHECK(done == CLIENT_BULK);
    CHECK(close(fd) == 0);
}

// Both connect before either sends, and the second sends first.
static void connect_concurrent(unsigned int echo) {
    int fds[2];
    unsigned int ports[2];
    char messages[2][64], names[2][16], replies[2][64];
    for (int i = 0; i < 2; i++) {
        fds[i] = socket(AF_VSOCK, SOCK_STREAM, 0);
        CHECK(fds[i] >= 0);
        ports[i] = connect_host(fds[i], echo);
        snprintf(names[i], sizeof(names[i]), "concurrent%d", i);
    }
    CHECK(ports[0] != ports[1]);
    for (int i = 1; i >= 0; i--) {
        send_name(fds[i], names[i], ports[i], messages[i], sizeof(messages[i]));
    }
    for (int i = 0; i < 2; i++) {
        read_to_eof(fds[i], replies[i], sizeof(replies[i]));
        CHECK(strcmp(replies[i], messages[i]) == 0);
        CHECK(close(fds[i]) == 0);
    }
}

static int serve(unsigned int port) {
    int listener = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_vm vsock_address = {
        .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_ANY, .svm_port = port};
    CHECK(bind(listener, (struct sockaddr *)&vsock_address, sizeof(vsock_address)) == 0);
    CHECK(listen(listener, 8) == 0);
    int nonblocking_listener = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(nonblocking_listener >= 0);
    vsock_address.svm_port = port + 3;
    CHECK(bind(nonblocking_listener, (struct sockaddr *)&vsock_address, sizeof(vsock_address)) ==
          0);
    CHECK(listen(nonblocking_listener, 128) == 0);
    set_nonblocking(nonblocking_listener);
    int ports_listener = socket(AF_VSOCK, SOCK_STREAM, 0);
    CHECK(ports_listener >= 0);
    vsock_address.svm_port = port + 4;
    CHECK(bind(ports_listener, (struct sockaddr *)&vsock_address, sizeof(vsock_address)) == 0);
    CHECK(listen(ports_listener, 1) == 0);
    printf("ready\n");
    fflush(stdout);
    serve_concurrent(listener);
    serve_churn(listener);
    serve_after_close(listener);
    serve_bulk(listener, BULK);
    serve_bulk(listener, SLOW);
    serve_local_shutdown(listener);
    CHECK(close(listener) == 0);
    serve_nonblocking(nonblocking_listener);
    CHECK(close(nonblocking_listener) == 0);
    printf("served\n");
    fflush(stdout);

    unsigned int echo, refused;
    read_host_ports(ports_listener, &echo, &refused);
    CHECK(close(ports_listener) == 0);
    connect_blocking(echo, refused);
    connect_nonblocking(echo, refused);
    connect_bulk(echo);
    connect_concurrent(echo);
    printf("connected\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: vsock PORT\n");
        return 2;
    }
    return serve((unsigned int)strtoul(argv[1], NULL, 10));
}
