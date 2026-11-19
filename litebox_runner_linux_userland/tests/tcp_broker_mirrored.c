// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// On a broker with `--network mirrored`, the host binds and names a guest's TCP sockets: the port
// in argv[1], which a host socket holds, is not the guest's, one bound to port 0 gets a port of its
// own, and the guest's connection to itself is named by loopback addresses at both ends.

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static struct sockaddr_in name(int fd, int peer) {
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    int result = peer ? getpeername(fd, (struct sockaddr *)&address, &length)
                      : getsockname(fd, (struct sockaddr *)&address, &length);
    assert(result == 0);
    assert(length == sizeof(address) && address.sin_family == AF_INET);
    return address;
}

static int same(struct sockaddr_in left, struct sockaddr_in right) {
    return left.sin_addr.s_addr == right.sin_addr.s_addr && left.sin_port == right.sin_port;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(listener >= 0);
    struct sockaddr_in any = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)strtoul(argv[1], NULL, 10)),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    assert(bind(listener, (const struct sockaddr *)&any, sizeof(any)) == -1);
    assert(errno == EADDRINUSE);
    any.sin_port = 0;
    assert(bind(listener, (const struct sockaddr *)&any, sizeof(any)) == 0);
    struct sockaddr_in bound = name(listener, 0);
    assert(bound.sin_addr.s_addr == htonl(INADDR_ANY) && bound.sin_port != 0);
    assert(listen(listener, 1) == 0);

    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(client >= 0);
    struct sockaddr_in loopback = {
        .sin_family = AF_INET,
        .sin_port = bound.sin_port,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    assert(connect(client, (const struct sockaddr *)&loopback, sizeof(loopback)) == 0);
    int server = accept(listener, NULL, NULL);
    assert(server >= 0);

    struct sockaddr_in client_name = name(client, 0);
    assert(client_name.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && client_name.sin_port != 0);
    assert(same(name(client, 1), loopback));
    assert(same(name(server, 0), loopback));
    assert(same(name(server, 1), client_name));

    assert(close(listener) == 0);
    int probe = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(probe >= 0);
    assert(connect(probe, (const struct sockaddr *)&loopback, sizeof(loopback)) == -1);
    assert(errno == ECONNREFUSED);
    assert(close(probe) == 0);

    // The accepted stream retains the stopped listener's wildcard bind, not just 127.0.0.1.
    struct sockaddr_in other_loopback = loopback;
    other_loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK + 1);
    int next = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(next >= 0);
    assert(bind(next, (const struct sockaddr *)&other_loopback, sizeof(other_loopback)) == -1);
    assert(errno == EADDRINUSE);

    char byte = 'x';
    assert(write(client, &byte, 1) == 1);
    byte = 0;
    assert(read(server, &byte, 1) == 1 && byte == 'x');
    assert(write(server, &byte, 1) == 1);
    byte = 0;
    assert(read(client, &byte, 1) == 1 && byte == 'x');

    assert(close(server) == 0);
    assert(bind(next, (const struct sockaddr *)&other_loopback, sizeof(other_loopback)) == 0);
    assert(close(next) == 0 && close(client) == 0);
    printf("tcp broker mirrored ok\n");
    return 0;
}
