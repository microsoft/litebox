// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that Unix sequenced-packet sockets keep record boundaries over a connection.

#include "helpers.h"
#include <signal.h>
#include <stddef.h>
#include <sys/un.h>

static void expect_recv_record(int fd, const char *expected, const char *op) {
    char buf[64];
    size_t expected_len = strlen(expected);

    memset(buf, 0, sizeof(buf));
    errno = 0;
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n < 0) {
        die(op);
    }
    if ((size_t)n != expected_len || memcmp(buf, expected, expected_len) != 0) {
        fprintf(stderr, "FAIL: %s expected '%s' (%zu bytes), got '%.*s' (%zd bytes)\n", op,
                expected, expected_len, (int)n, buf, n);
        exit(1);
    }
}

static void send_record(int fd, const char *record, const char *op) {
    size_t len = strlen(record);
    TEST_ASSERT(send(fd, record, len, MSG_NOSIGNAL | MSG_EOR) == (ssize_t)len, op);
}

static socklen_t abstract_address(struct sockaddr_un *address, const char *name) {
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    int len = snprintf(address->sun_path + 1, sizeof(address->sun_path) - 1, "lb_seqpacket_%s_%d",
                       name, getpid());
    return offsetof(struct sockaddr_un, sun_path) + 1 + len;
}

static int listen_on(int type, const struct sockaddr_un *address, socklen_t length) {
    int fd = socket(AF_UNIX, type, 0);
    TEST_ASSERT(fd >= 0, "socket(listener)");
    TEST_ASSERT(bind(fd, (const struct sockaddr *)address, length) == 0, "bind(listener)");
    TEST_ASSERT(listen(fd, 4) == 0, "listen(listener)");
    return fd;
}

static void test_pair_keeps_records(void) {
    int sv[2];
    make_socket_pair(SOCK_SEQPACKET, sv);

    int type = 0;
    socklen_t length = sizeof(type);
    TEST_ASSERT(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &type, &length) == 0, "SO_TYPE");
    TEST_ASSERT(type == SOCK_SEQPACKET, "SO_TYPE is SOCK_SEQPACKET");

    send_record(sv[1], "abc", "send first record");
    TEST_ASSERT(send(sv[1], "", 0, MSG_NOSIGNAL) == 0, "send empty record");
    send_record(sv[1], "defgh", "send long record");
    send_record(sv[1], "peeked", "send peeked record");

    expect_recv_record(sv[0], "abc", "recv first record");

    char buf[8];
    errno = 0;
    TEST_ASSERT(recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT) == 0, "recv empty record");

    struct iovec iov = {.iov_base = buf, .iov_len = 2};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    TEST_ASSERT(recvmsg(sv[0], &msg, MSG_DONTWAIT) == 2, "recvmsg truncated record");
    TEST_ASSERT(memcmp(buf, "de", 2) == 0, "truncated record prefix");
    TEST_ASSERT(msg.msg_flags & MSG_TRUNC, "recvmsg reports MSG_TRUNC");

    TEST_ASSERT(recv(sv[0], buf, 2, MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC) == 6,
                "peek reports the record length");
    expect_recv_record(sv[0], "peeked", "recv peeked record");
    expect_recv_errno(sv[0], EAGAIN, "recv drained pair");

    close_pair(sv);
}

static void test_peer_close_ends_receives(void) {
    int sv[2];
    make_socket_pair(SOCK_SEQPACKET, sv);

    send_record(sv[1], "last", "send before close");
    close(sv[1]);

    expect_poll_has(sv[0], POLLIN | POLLRDHUP, POLLIN | POLLRDHUP | POLLHUP, "poll after close");
    expect_recv_record(sv[0], "last", "recv queued record after close");
    // Unlike a datagram socket, a disconnected one reports the end even without waiting.
    char buf[8];
    TEST_ASSERT(recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT) == 0, "nonblocking recv after close");
    expect_recv_eof(sv[0], "blocking recv after close");
    expect_send_errno(sv[0], EPIPE, "send after peer close");

    close(sv[0]);
}

static volatile sig_atomic_t sigpipe_count;

static void on_sigpipe(int signal) {
    (void)signal;
    sigpipe_count++;
}

// Like a datagram socket, and unlike a stream socket, a broken pipe raises no SIGPIPE.
static void test_broken_pipe_raises_no_sigpipe(void) {
    int sv[2];
    make_socket_pair(SOCK_SEQPACKET, sv);
    close(sv[1]);

    struct sigaction action = {.sa_handler = on_sigpipe};
    struct sigaction previous;
    TEST_ASSERT(sigaction(SIGPIPE, &action, &previous) == 0, "catch SIGPIPE");
    errno = 0;
    TEST_ASSERT(send(sv[0], "x", 1, 0) == -1 && errno == EPIPE, "send to closed peer");
    errno = 0;
    TEST_ASSERT(write(sv[0], "x", 1) == -1 && errno == EPIPE, "write to closed peer");
    TEST_ASSERT(sigpipe_count == 0, "broken pipe raised no SIGPIPE");
    TEST_ASSERT(sigaction(SIGPIPE, &previous, NULL) == 0, "restore SIGPIPE");

    close(sv[0]);
}

static void test_peer_shutdown_write_ends_receives(void) {
    int sv[2];
    make_socket_pair(SOCK_SEQPACKET, sv);

    expect_sys_shutdown(sv[1], SHUT_WR, "peer shutdown(SHUT_WR)");
    expect_send_errno(sv[1], EPIPE, "send after SHUT_WR");
    expect_poll_has(sv[0], POLLIN | POLLRDHUP, POLLIN | POLLRDHUP, "poll after peer SHUT_WR");
    char buf[8];
    TEST_ASSERT(recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT) == 0,
                "nonblocking recv after peer SHUT_WR");
    send_record(sv[0], "back", "send toward shut peer");
    expect_recv_record(sv[1], "back", "shut peer still receives");

    close_pair(sv);
}

static void test_unconnected_socket(void) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    TEST_ASSERT(fd >= 0, "socket(SOCK_SEQPACKET)");

    expect_poll_has(fd, POLLOUT, POLLOUT | POLLHUP, "poll unconnected");
    expect_send_errno(fd, ENOTCONN, "send unconnected");
    expect_recv_errno(fd, ENOTCONN, "recv unconnected");
    struct sockaddr_un address;
    socklen_t length = abstract_address(&address, "nobody");
    errno = 0;
    TEST_ASSERT(sendto(fd, "x", 1, MSG_NOSIGNAL, (struct sockaddr *)&address, length) == -1 &&
                    errno == ENOTCONN,
                "sendto unconnected");
    struct sockaddr_un unnamed = {.sun_family = AF_UNIX};
    errno = 0;
    TEST_ASSERT(sendto(fd, "x", 1, MSG_NOSIGNAL, (struct sockaddr *)&unnamed,
                       sizeof(sa_family_t)) == -1 &&
                    errno == ENOTCONN,
                "sendto unconnected to an unnamed address");

    close(fd);
}

static void test_listen_accept_connect(void) {
    struct sockaddr_un address;
    socklen_t address_length = abstract_address(&address, "listen");
    int listener = listen_on(SOCK_SEQPACKET, &address, address_length);
    expect_recv_errno(listener, ENOTCONN, "recv on listener");

    int client = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    TEST_ASSERT(client >= 0, "socket(client)");
    TEST_ASSERT(connect(client, (struct sockaddr *)&address, address_length) == 0, "connect");
    int server = accept(listener, NULL, NULL);
    TEST_ASSERT(server >= 0, "accept");

    int type = 0;
    socklen_t length = sizeof(type);
    TEST_ASSERT(getsockopt(server, SOL_SOCKET, SO_TYPE, &type, &length) == 0, "SO_TYPE");
    TEST_ASSERT(type == SOCK_SEQPACKET, "accepted socket is SOCK_SEQPACKET");

    send_record(server, "one", "server send one");
    send_record(server, "two", "server send two");
    char buf[16];
    struct sockaddr_un source;
    socklen_t source_length = sizeof(source);
    memset(&source, 0, sizeof(source));
    TEST_ASSERT(recvfrom(client, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&source,
                         &source_length) == 3 &&
                    memcmp(buf, "one", 3) == 0,
                "client recvfrom");
    TEST_ASSERT(source_length == address_length &&
                    memcmp(&source, &address, address_length) == 0,
                "record source is the listener's name");
    expect_recv_record(client, "two", "client recv two");

    // A connected socket ignores the address it is given.
    struct sockaddr_un elsewhere;
    socklen_t elsewhere_length = abstract_address(&elsewhere, "elsewhere");
    TEST_ASSERT(sendto(client, "hi", 2, MSG_NOSIGNAL, (struct sockaddr *)&elsewhere,
                       elsewhere_length) == 2,
                "sendto ignores the address");
    expect_recv_record(server, "hi", "server recv");
    struct sockaddr_un unnamed = {.sun_family = AF_UNIX};
    TEST_ASSERT(sendto(client, "hey", 3, MSG_NOSIGNAL, (struct sockaddr *)&unnamed,
                       sizeof(sa_family_t)) == 3,
                "sendto ignores an unnamed address");
    expect_recv_record(server, "hey", "server recv after unnamed sendto");

    close(server);
    close(client);
    close(listener);
}

static void test_wrong_type_connect(void) {
    struct sockaddr_un address;
    socklen_t length = abstract_address(&address, "stream");
    int stream_listener = listen_on(SOCK_STREAM, &address, length);
    int seqpacket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    TEST_ASSERT(seqpacket >= 0, "socket(seqpacket)");
    errno = 0;
    TEST_ASSERT(connect(seqpacket, (struct sockaddr *)&address, length) == -1 &&
                    errno == ECONNREFUSED,
                "seqpacket connect to an abstract stream name");
    close(seqpacket);
    close(stream_listener);

    char path[64];
    snprintf(path, sizeof(path), "/tmp/lb_seqpacket_%d", getpid());
    unlink(path);
    struct sockaddr_un path_address = {.sun_family = AF_UNIX};
    strncpy(path_address.sun_path, path, sizeof(path_address.sun_path) - 1);
    int path_listener = listen_on(SOCK_STREAM, &path_address, sizeof(path_address));
    seqpacket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    TEST_ASSERT(seqpacket >= 0, "socket(seqpacket)");
    errno = 0;
    TEST_ASSERT(connect(seqpacket, (struct sockaddr *)&path_address, sizeof(path_address)) == -1 &&
                    errno == EPROTOTYPE,
                "seqpacket connect to a stream path");
    close(seqpacket);
    close(path_listener);
    unlink(path);
}

int main(void) {
    printf("== unix seqpacket tests ==\n");

    test_pair_keeps_records();
    test_peer_close_ends_receives();
    test_broken_pipe_raises_no_sigpipe();
    test_peer_shutdown_write_ends_receives();
    test_unconnected_socket();
    test_listen_accept_connect();
    test_wrong_type_connect();

    printf("All unix seqpacket tests passed.\n");
    return 0;
}
