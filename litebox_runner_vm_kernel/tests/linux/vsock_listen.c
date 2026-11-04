// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// AF_VSOCK sockets where the broker has vsock, with no host client (see vsock.c): creation
// and bind rules, names, address checks, unreachable connects, unconnected sends and shutdowns,
// socket options, and a listener inherited across fork and exec (as `PROGRAM child FD PORT`).

#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

// Checks that `fd` listens on `port`, with no connection waiting.
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

// Poll and level-triggered epoll report an unconnected socket only writable, as Linux does: not
// hung up, unlike an unconnected Unix stream socket.
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
    CHECK_ERRNO(socket(AF_VSOCK, SOCK_STREAM, 6), EPROTONOSUPPORT);
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, PF_VSOCK);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    int pair[2];
    CHECK_ERRNO(socketpair(AF_VSOCK, SOCK_STREAM, 0, pair), EOPNOTSUPP);
}

static void bind_rules(void) {
    int fd = vsock_socket(0);
    struct sockaddr_vm address = local_address(fd);
    CHECK(address.svm_cid == VMADDR_CID_ANY && address.svm_port == VMADDR_PORT_ANY);
    CHECK_ERRNO(shutdown(fd, SHUT_RDWR), ENOTCONN);
    check_writable_only(fd);

    address = vsock_address(VMADDR_CID_ANY, PORT);
    CHECK_ERRNO(bind(fd, (struct sockaddr *)&address, sizeof(address) - 1), EINVAL);
    struct sockaddr_un unix_address = {.sun_family = AF_UNIX, .sun_path = "/tmp/vsock"};
    CHECK_ERRNO(bind(fd, (struct sockaddr *)&unix_address, sizeof(unix_address)), EINVAL);
    CHECK_ERRNO(bind_vsock(fd, VMADDR_CID_HOST, PORT), EADDRNOTAVAIL);
    CHECK_ERRNO(listen(fd, 1), EINVAL);

    CHECK(bind_vsock(fd, VMADDR_CID_ANY, PORT) == 0);
    CHECK_ERRNO(bind_vsock(fd, VMADDR_CID_ANY, PORT + 1), EINVAL);
    CHECK_ERRNO(shutdown(fd, SHUT_RD), ENOTCONN);
    check_writable_only(fd);
    int other = vsock_socket(0);
    CHECK_ERRNO(bind_vsock(other, VMADDR_CID_ANY, PORT), EADDRINUSE);
    CHECK(bind_vsock(other, VMADDR_CID_ANY, VMADDR_PORT_ANY) == 0);
    address = local_address(other);
    CHECK(address.svm_cid == VMADDR_CID_ANY && address.svm_port > 1023 &&
          address.svm_port != VMADDR_PORT_ANY && address.svm_port != PORT);
    CHECK(close(other) == 0);
    CHECK(close(fd) == 0);
    fd = vsock_socket(0);
    CHECK(bind_vsock(fd, VMADDR_CID_ANY, PORT) == 0);
    CHECK(close(fd) == 0);
}

enum { CONNECT, SENDTO, SENDMSG, BIND };

// As in Linux, on an unconnected socket: an address is copied first (EINVAL
// above 128 bytes, a sendmsg clamping it, and EFAULT), then a connect or bind
// fails with EINVAL unless it is a vsock address, and a send fails with
// EOPNOTSUPP if it has an address at all (one of length 0 is none).
static void address_rules(void) {
    struct sockaddr_vm bad_flags = vsock_address(VMADDR_CID_HOST, PORT);
    bad_flags.svm_flags = 2;
    struct sockaddr_vm vsock = vsock_address(VMADDR_CID_ANY, PORT);
    struct sockaddr_in inet = {.sin_family = AF_INET};
    struct sockaddr_in6 inet6 = {.sin6_family = AF_INET6};
    static unsigned char big[200];
    memcpy(big, &vsock, sizeof(vsock));
    // Inaccessible rather than unmapped: on the userland runner, a page the guest unmaps may
    // become the host's.
    void *inaccessible = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    const struct {
        int op;
        const void *address;
        socklen_t len;
        int error;
    } cases[] = {
        {CONNECT, &bad_flags, sizeof(bad_flags), EINVAL},
        {CONNECT, &vsock, sizeof(vsock) - 1, EINVAL},
        {CONNECT, &inet, sizeof(inet), EINVAL},
        {CONNECT, &inet6, sizeof(inet6), EINVAL},
        {CONNECT, NULL, 0, EINVAL},
        {CONNECT, big, 129, EINVAL},
        {CONNECT, inaccessible, sizeof(vsock), EFAULT},
        {SENDTO, &vsock, sizeof(vsock) - 1, EOPNOTSUPP},
        {SENDTO, &inet6, sizeof(inet6), EOPNOTSUPP},
        {SENDTO, &vsock, 0, ENOTCONN},
        {SENDTO, big, 129, EINVAL},
        {SENDTO, inaccessible, sizeof(vsock), EFAULT},
        {SENDMSG, big, sizeof(big), EOPNOTSUPP},
        {SENDMSG, big, 0, ENOTCONN},
        {SENDMSG, inaccessible, sizeof(vsock), EFAULT},
        {BIND, &inet6, sizeof(inet6), EINVAL},
        {BIND, &vsock, sizeof(vsock) - 1, EINVAL},
        {BIND, big, 129, EINVAL},
        {BIND, inaccessible, sizeof(vsock), EFAULT},
    };
    int fd = vsock_socket(0);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct sockaddr *address = (struct sockaddr *)cases[i].address;
        socklen_t len = cases[i].len;
        struct iovec iov = {.iov_base = "x", .iov_len = 1};
        struct msghdr msg = {.msg_name = address, .msg_namelen = len, .msg_iov = &iov,
                             .msg_iovlen = 1};
        long result;
        errno = 0;
        switch (cases[i].op) {
        case CONNECT: result = connect(fd, address, len); break;
        case SENDTO: result = sendto(fd, "x", 1, MSG_NOSIGNAL, address, len); break;
        case SENDMSG: result = sendmsg(fd, &msg, MSG_NOSIGNAL); break;
        default: result = bind(fd, address, len); break;
        }
        if (result != -1 || errno != cases[i].error) {
            printf("FAIL case %zu: %ld, errno %d, expected %d\n", i, result, errno,
                   cases[i].error);
            exit(1);
        }
    }
    // Nothing bound it.
    struct sockaddr_vm name = local_address(fd);
    CHECK(name.svm_cid == VMADDR_CID_ANY && name.svm_port == VMADDR_PORT_ANY);
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

    // Only the host is reachable, whether or not the connect would wait; a failed connect binds
    // no port and leaves no error.
    int client = vsock_socket(0);
    int nonblocking_client = vsock_socket(SOCK_NONBLOCK);
    struct sockaddr_vm address = vsock_address(3, PORT);
    CHECK_ERRNO(connect(client, (struct sockaddr *)&address, sizeof(address)), ENETUNREACH);
    CHECK_ERRNO(connect(nonblocking_client, (struct sockaddr *)&address, sizeof(address)),
                ENETUNREACH);
    check_writable_only(client);
    check_writable_only(nonblocking_client);
    struct sockaddr_vm unbound = local_address(nonblocking_client);
    CHECK(unbound.svm_cid == VMADDR_CID_ANY && unbound.svm_port == VMADDR_PORT_ANY);
    int error = -1;
    socklen_t error_len = sizeof(error);
    CHECK(getsockopt(nonblocking_client, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 &&
          error == 0);
    CHECK(close(nonblocking_client) == 0);
    CHECK_ERRNO(sendto(client, "x", 1, 0, (struct sockaddr *)&address, sizeof(address)),
                EOPNOTSUPP);
    CHECK_ERRNO(send(client, "x", 1, MSG_NOSIGNAL), ENOTCONN);
    // As in Linux, the socket's state decides before the address.
    CHECK_ERRNO(connect(fd, (struct sockaddr *)&address, sizeof(address)), EINVAL);
    struct sockaddr_un unix_path = {.sun_family = AF_UNIX, .sun_path = "/tmp/vsock"};
    CHECK_ERRNO(connect(client, (struct sockaddr *)&unix_path, sizeof(unix_path)), EINVAL);
    CHECK(close(client) == 0);

    // A listener does not shut down, and still listens.
    CHECK_ERRNO(shutdown(fd, SHUT_WR), ENOTCONN);
    CHECK(poll(&poll_fd, 1, 0) == 0);
    check_listener(fd, PORT);

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
    address_rules();
    int fd = listener();
    inherit(argv[0], fd);
    CHECK(close(fd) == 0);
    printf("vsock-listen ok\n");
    return 0;
}
