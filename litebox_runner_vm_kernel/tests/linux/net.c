// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Sockets through the broker's network stack. See net.json.
//
//   net loopback      TCP and UDP between sockets of this process, at
//                     127.0.0.1 and the guest's own address, 10.0.2.15.
//   net external IP PORT
//                     TCP to an echo server outside the VM, through the
//                     network device: what it writes comes back, through
//                     blocking calls and through poll.
//
// Guest connections complete within the broker call that makes them; external
// ones wait for the network, ended by the broker's readiness notifications.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL %s:%d: %s (errno %d: %s)\n", __FILE__, __LINE__,      \
                   #cond, errno, strerror(errno));                             \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static struct sockaddr_in address(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, ip, &a.sin_addr) == 1);
    return a;
}

static void read_exactly(int fd, char *buffer, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buffer + done, len - done);
        CHECK(n > 0);
        done += (size_t)n;
    }
}

static void write_all(int fd, const char *buffer, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buffer + done, len - done);
        CHECK(n > 0);
        done += (size_t)n;
    }
}

// A listener on 0.0.0.0, a nonblocking client to `ip`, and data both ways,
// then the client's half-close reaching the server as the end of stream.
static void tcp_loopback(const char *ip) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_in any = address("0.0.0.0", 0);
    CHECK(bind(listener, (struct sockaddr *)&any, sizeof(any)) == 0);
    CHECK(listen(listener, 4) == 0);
    socklen_t len = sizeof(any);
    CHECK(getsockname(listener, (struct sockaddr *)&any, &len) == 0);
    CHECK(ntohs(any.sin_port) != 0);

    int client = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client >= 0);
    CHECK(fcntl(client, F_SETFL, O_NONBLOCK) == 0);
    struct sockaddr_in server = address(ip, ntohs(any.sin_port));
    int rc = connect(client, (struct sockaddr *)&server, sizeof(server));
    CHECK(rc == 0 || errno == EINPROGRESS);
    struct pollfd pfd = {.fd = client, .events = POLLOUT};
    CHECK(poll(&pfd, 1, 5000) == 1 && (pfd.revents & POLLOUT));
    int error = -1;
    len = sizeof(error);
    CHECK(getsockopt(client, SOL_SOCKET, SO_ERROR, &error, &len) == 0);
    CHECK(error == 0);
    CHECK(fcntl(client, F_SETFL, 0) == 0);

    struct sockaddr_in peer;
    len = sizeof(peer);
    int accepted = accept(listener, (struct sockaddr *)&peer, &len);
    CHECK(accepted >= 0);
    struct sockaddr_in local;
    len = sizeof(local);
    CHECK(getsockname(client, (struct sockaddr *)&local, &len) == 0);
    CHECK(peer.sin_port == local.sin_port);
    CHECK(peer.sin_addr.s_addr == server.sin_addr.s_addr);

    int one = 1;
    CHECK(setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);

    char buffer[256];
    write_all(client, "ping", 4);
    read_exactly(accepted, buffer, 4);
    CHECK(memcmp(buffer, "ping", 4) == 0);

    // A large transfer, peeked at first.
    static char big[100000], got[sizeof(big)];
    for (size_t i = 0; i < sizeof(big); i++) {
        big[i] = (char)(i * 7);
    }
    write_all(accepted, big, sizeof(big));
    CHECK(recv(client, buffer, 16, MSG_PEEK) == 16);
    CHECK(memcmp(buffer, big, 16) == 0);
    read_exactly(client, got, sizeof(got));
    CHECK(memcmp(got, big, sizeof(big)) == 0);

    CHECK(shutdown(client, SHUT_WR) == 0);
    CHECK(read(accepted, buffer, sizeof(buffer)) == 0);
    write_all(accepted, "pong", 4);
    read_exactly(client, buffer, 4);
    CHECK(memcmp(buffer, "pong", 4) == 0);
    close(accepted);
    CHECK(read(client, buffer, sizeof(buffer)) == 0);
    close(client);
    close(listener);
    printf("tcp %s: ok\n", ip);
}

// Nobody listens: the connection is refused.
static void tcp_refused(void) {
    int client = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client >= 0);
    struct sockaddr_in server = address("127.0.0.1", 9);
    CHECK(connect(client, (struct sockaddr *)&server, sizeof(server)) == -1);
    CHECK(errno == ECONNREFUSED);
    close(client);
    printf("tcp refused: ok\n");
}

static void udp_loopback(void) {
    int a = socket(AF_INET, SOCK_DGRAM, 0);
    int b = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(a >= 0 && b >= 0);
    struct sockaddr_in any = address("0.0.0.0", 0);
    CHECK(bind(b, (struct sockaddr *)&any, sizeof(any)) == 0);
    socklen_t len = sizeof(any);
    CHECK(getsockname(b, (struct sockaddr *)&any, &len) == 0);

    struct sockaddr_in to = address("127.0.0.1", ntohs(any.sin_port));
    CHECK(sendto(a, "hello", 5, 0, (struct sockaddr *)&to, sizeof(to)) == 5);
    char buffer[64];
    struct sockaddr_in from;
    len = sizeof(from);
    CHECK(recvfrom(b, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &len) == 5);
    CHECK(memcmp(buffer, "hello", 5) == 0);
    CHECK(from.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

    // A reply to the sender, and a datagram larger than an Ethernet frame.
    static char big[8000];
    memset(big, 'x', sizeof(big));
    CHECK(sendto(b, big, sizeof(big), 0, (struct sockaddr *)&from, len) == (ssize_t)sizeof(big));
    CHECK(recv(a, buffer, sizeof(buffer), MSG_TRUNC) == (ssize_t)sizeof(big));
    close(a);
    close(b);
    printf("udp: ok\n");
}

static void external(const char *ip, int port) {
    int client = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client >= 0);
    struct sockaddr_in server = address(ip, port);
    CHECK(connect(client, (struct sockaddr *)&server, sizeof(server)) == 0);
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    CHECK(getsockname(client, (struct sockaddr *)&local, &len) == 0);
    CHECK(local.sin_addr.s_addr == inet_addr("10.0.2.15"));

    // Blocking: each read waits for the echo.
    char line[1000], echoed[sizeof(line)];
    for (int round = 0; round < 50; round++) {
        memset(line, 'a' + round % 26, sizeof(line));
        write_all(client, line, sizeof(line));
        read_exactly(client, echoed, sizeof(echoed));
        CHECK(memcmp(line, echoed, sizeof(line)) == 0);
    }
    // Nothing more is coming: poll times out.
    struct pollfd idle = {.fd = client, .events = POLLIN};
    CHECK(poll(&idle, 1, 200) == 0);

    // Enough to take several segments and windows each way.
    static char sent[200000], received[sizeof(sent)];
    for (size_t i = 0; i < sizeof(sent); i++) {
        sent[i] = (char)(i * 13 + 1);
    }
    size_t written = 0, read_ = 0;
    CHECK(fcntl(client, F_SETFL, O_NONBLOCK) == 0);
    while (read_ < sizeof(received)) {
        struct pollfd pfd = {.fd = client, .events = POLLIN};
        if (written < sizeof(sent)) {
            pfd.events |= POLLOUT;
        }
        CHECK(poll(&pfd, 1, 10000) == 1);
        short revents = pfd.revents;
        if (revents & POLLOUT) {
            ssize_t n = write(client, sent + written, sizeof(sent) - written);
            CHECK(n > 0 || errno == EAGAIN);
            if (n > 0) {
                written += (size_t)n;
            }
        }
        if (revents & POLLIN) {
            ssize_t n = read(client, received + read_, sizeof(received) - read_);
            CHECK(n > 0 || errno == EAGAIN);
            if (n > 0) {
                read_ += (size_t)n;
            }
        }
    }
    CHECK(memcmp(sent, received, sizeof(sent)) == 0);
    close(client);
    printf("external %s:%d: ok\n", ip, port);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && strcmp(argv[1], "loopback") == 0) {
        tcp_loopback("127.0.0.1");
        tcp_loopback("10.0.2.15");
        tcp_refused();
        udp_loopback();
    } else if (argc == 4 && strcmp(argv[1], "external") == 0) {
        external(argv[2], atoi(argv[3]));
    } else {
        fprintf(stderr, "usage: net loopback | external IP PORT\n");
        return 2;
    }
    return 0;
}
