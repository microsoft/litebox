// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks LiteBox's AF_VSOCK stream sockets with a vsock device but without a host client (see
// vsock.c for those): creation and bind rules, names, unreachable connects, sends and shutdowns
// of unconnected sockets, socket options, and a listener that forked and exec'd children inherit. Run with no
// arguments; it execs itself as `PROGRAM child FD PORT` to check the inherited listener.

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
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

// Fails with `error`.
#define CHECK_ERRNO(call, error)                                                                   \
    do {                                                                                           \
        errno = 0;                                                                                 \
        CHECK((call) == -1 && errno == (error));                                                   \
    } while (0)

#define PORT 5000

static struct sockaddr_vm vsock_address(unsigned int cid, unsigned int port) {
    return (struct sockaddr_vm){.svm_family = AF_VSOCK, .svm_cid = cid, .svm_port = port};
}

static int vsock_socket(int flags) {
    int fd = socket(AF_VSOCK, SOCK_STREAM | flags, 0);
    CHECK(fd >= 0);
    return fd;
}

static int bind_vsock(int fd, unsigned int cid, unsigned int port) {
    struct sockaddr_vm address = vsock_address(cid, port);
    return bind(fd, (struct sockaddr *)&address, sizeof(address));
}

static struct sockaddr_vm local_address(int fd) {
    struct sockaddr_vm address;
    memset(&address, 0xff, sizeof(address));
    socklen_t len = sizeof(address);
    CHECK(getsockname(fd, (struct sockaddr *)&address, &len) == 0);
    CHECK(len == sizeof(address));
    CHECK(address.svm_family == AF_VSOCK);
    return address;
}

// Checks that `fd` listens on PORT, with no connection waiting.
static void check_listener(int fd, unsigned int port) {
    struct sockaddr_vm address = local_address(fd);
    CHECK(address.svm_cid == VMADDR_CID_ANY && address.svm_port == port);
    int value = 0;
    socklen_t len = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &len) == 0 && value == SOCK_STREAM);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &value, &len) == 0 && value == AF_VSOCK);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &value, &len) == 0 && value == 0);
    CHECK_ERRNO(accept4(fd, NULL, NULL, SOCK_NONBLOCK), EAGAIN);
}

// Checks that no `shutdown` of the unconnected `fd` succeeds.
static void check_no_shutdown(int fd) {
    CHECK_ERRNO(shutdown(fd, SHUT_RD), ENOTCONN);
    CHECK_ERRNO(shutdown(fd, SHUT_WR), ENOTCONN);
    CHECK_ERRNO(shutdown(fd, SHUT_RDWR), ENOTCONN);
}

// Checks that poll and level-triggered epoll report the unconnected `fd` only writable, as Linux
// does, whether or not it is bound: not hung up, unlike an unconnected Unix stream socket.
static void check_writable_only(int fd) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN | POLLOUT | POLLRDHUP};
    CHECK(poll(&poll_fd, 1, 0) == 1 && poll_fd.revents == POLLOUT);
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epfd >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP, .data.fd = fd};
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) == 0);
    CHECK(epoll_wait(epfd, &event, 1, 0) == 1 && event.events == EPOLLOUT);
    CHECK(close(epfd) == 0);
}

static void creation_rules(void) {
    CHECK_ERRNO(socket(AF_VSOCK, SOCK_DGRAM, 0), ESOCKTNOSUPPORT);
    CHECK_ERRNO(socket(AF_VSOCK, SOCK_SEQPACKET, 0), ESOCKTNOSUPPORT);
    CHECK_ERRNO(socket(AF_VSOCK, SOCK_STREAM, 6), EPROTONOSUPPORT);
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, PF_VSOCK);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    int pair[2];
    CHECK_ERRNO(socketpair(AF_VSOCK, SOCK_STREAM, 0, pair), EOPNOTSUPP);
}

static void bind_rules(void) {
    int fd = vsock_socket(0);
    // Unbound: no address.
    struct sockaddr_vm address = local_address(fd);
    CHECK(address.svm_cid == VMADDR_CID_ANY && address.svm_port == VMADDR_PORT_ANY);
    check_no_shutdown(fd);
    check_writable_only(fd);

    address = vsock_address(VMADDR_CID_ANY, PORT);
    CHECK_ERRNO(bind(fd, (struct sockaddr *)&address, sizeof(address) - 1), EINVAL);
    struct sockaddr_un unix_address = {.sun_family = AF_UNIX, .sun_path = "/tmp/vsock"};
    CHECK_ERRNO(bind(fd, (struct sockaddr *)&unix_address, sizeof(unix_address)), EINVAL);
    address.svm_flags = 0x80;
    CHECK_ERRNO(bind(fd, (struct sockaddr *)&address, sizeof(address)), EINVAL);
    CHECK_ERRNO(bind_vsock(fd, VMADDR_CID_HOST, PORT), EADDRNOTAVAIL);
    CHECK_ERRNO(bind_vsock(fd, VMADDR_CID_LOCAL, PORT), EADDRNOTAVAIL);
    CHECK_ERRNO(listen(fd, 1), EINVAL);

    CHECK(bind_vsock(fd, VMADDR_CID_ANY, PORT) == 0);
    CHECK_ERRNO(bind_vsock(fd, VMADDR_CID_ANY, PORT + 1), EINVAL);
    check_no_shutdown(fd);
    check_writable_only(fd);
    int other = vsock_socket(0);
    CHECK_ERRNO(bind_vsock(other, VMADDR_CID_ANY, PORT), EADDRINUSE);
    CHECK(bind_vsock(other, VMADDR_CID_ANY, VMADDR_PORT_ANY) == 0);
    address = local_address(other);
    CHECK(address.svm_cid == VMADDR_CID_ANY && address.svm_port > 1023 &&
          address.svm_port != VMADDR_PORT_ANY && address.svm_port != PORT);
    CHECK(close(other) == 0);
    CHECK(close(fd) == 0);
    // Closing releases the port.
    fd = vsock_socket(0);
    CHECK(bind_vsock(fd, VMADDR_CID_ANY, PORT) == 0);
    CHECK(close(fd) == 0);
}

// Returns a nonblocking listener on PORT, after checking what it refuses.
static int listener(void) {
    int fd = vsock_socket(0);
    CHECK(bind_vsock(fd, VMADDR_CID_ANY, PORT) == 0);
    CHECK(listen(fd, 8) == 0);
    int on = 1;
    CHECK(ioctl(fd, FIONBIO, &on) == 0);
    check_listener(fd, PORT);
    struct sockaddr_vm peer;
    socklen_t len = sizeof(peer);
    CHECK_ERRNO(accept(fd, (struct sockaddr *)&peer, &len), EAGAIN);
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    CHECK(poll(&poll_fd, 1, 0) == 0);
    CHECK_ERRNO(getpeername(fd, (struct sockaddr *)&peer, &len), ENOTCONN);

    // Only the host is reachable, not the guest itself or other guests, whether or not the
    // connect would wait; it binds no port, and leaves no error, and the socket stays only
    // writable.
    int client = vsock_socket(0);
    int nonblocking_client = vsock_socket(SOCK_NONBLOCK);
    const unsigned int cids[] = {VMADDR_CID_LOCAL, 3};
    for (size_t i = 0; i < sizeof(cids) / sizeof(cids[0]); i++) {
        struct sockaddr_vm address = vsock_address(cids[i], PORT);
        CHECK_ERRNO(connect(client, (struct sockaddr *)&address, sizeof(address)), ENETUNREACH);
        CHECK_ERRNO(connect(nonblocking_client, (struct sockaddr *)&address, sizeof(address)),
                    ENETUNREACH);
    }
    check_writable_only(client);
    check_writable_only(nonblocking_client);
    struct sockaddr_vm unbound = local_address(nonblocking_client);
    CHECK(unbound.svm_cid == VMADDR_CID_ANY && unbound.svm_port == VMADDR_PORT_ANY);
    int error = -1;
    socklen_t error_len = sizeof(error);
    CHECK(getsockopt(nonblocking_client, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 &&
          error == 0);
    CHECK(close(nonblocking_client) == 0);
    struct sockaddr_vm address = vsock_address(VMADDR_CID_LOCAL, PORT);
    CHECK_ERRNO(sendto(client, "x", 1, 0, (struct sockaddr *)&address, sizeof(address)),
                EOPNOTSUPP);
    CHECK_ERRNO(send(client, "x", 1, MSG_NOSIGNAL), ENOTCONN);
    // As in Linux, a listener fails by its state, and an address of another family is invalid
    // for a connect but refused like any other for a send.
    CHECK_ERRNO(connect(fd, (struct sockaddr *)&address, sizeof(address)), EINVAL);
    CHECK_ERRNO(sendto(fd, "x", 1, 0, (struct sockaddr *)&address, sizeof(address)), EOPNOTSUPP);
    struct sockaddr_un unix_path = {.sun_family = AF_UNIX, .sun_path = "/tmp/vsock"};
    CHECK_ERRNO(connect(client, (struct sockaddr *)&unix_path, sizeof(unix_path)), EINVAL);
    CHECK_ERRNO(sendto(client, "x", 1, 0, (struct sockaddr *)&unix_path, sizeof(unix_path)),
                EOPNOTSUPP);
    CHECK(close(client) == 0);

    // A listener does not shut down, and still listens.
    check_no_shutdown(fd);
    CHECK(poll(&poll_fd, 1, 0) == 0);
    check_listener(fd, PORT);

    // Options at the AF_VSOCK level are not supported.
    unsigned long long size = 4096;
    CHECK_ERRNO(setsockopt(fd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &size, sizeof(size)),
                ENOPROTOOPT);
    socklen_t size_len = sizeof(size);
    CHECK_ERRNO(getsockopt(fd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &size, &size_len),
                ENOPROTOOPT);
    return fd;
}

// A forked child, and a child it execs, share the listener.
static void inherit(const char *program, int fd) {
    fflush(stdout);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        check_listener(fd, PORT);
        char fd_arg[16], port_arg[16];
        snprintf(fd_arg, sizeof(fd_arg), "%d", fd);
        snprintf(port_arg, sizeof(port_arg), "%d", PORT);
        char *const argv[] = {(char *)program, "child", fd_arg, port_arg, NULL};
        execv(program, argv);
        _exit(99);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check_listener(fd, PORT);
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "child") == 0) {
        check_listener(atoi(argv[2]), (unsigned int)atoi(argv[3]));
        return 0;
    }
    creation_rules();
    bind_rules();
    int fd = listener();
    inherit(argv[0], fd);
    CHECK(close(fd) == 0);
    printf("vsock-listen ok\n");
    return 0;
}
