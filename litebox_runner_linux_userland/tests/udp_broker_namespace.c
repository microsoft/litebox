// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void wait_readable(int fd) {
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    assert(poll(&ready, 1, 5000) == 1);
    assert((ready.revents & POLLIN) != 0);
}

static int run_server(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = 0,
    };
    assert(inet_pton(AF_INET, "10.0.2.15", &local.sin_addr) == 1);
    assert(bind(fd, (const struct sockaddr *)&local, sizeof(local)) == 0);
    socklen_t length = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &length) == 0);
    assert(local.sin_addr.s_addr == inet_addr("10.0.2.15"));
    assert(local.sin_port != 0);
    printf("LISTEN %u\n", (unsigned int)ntohs(local.sin_port));

    wait_readable(fd);
    char request[7] = {0};
    struct sockaddr_in source;
    length = sizeof(source);
    assert(recvfrom(fd, request, sizeof(request), 0,
                    (struct sockaddr *)&source, &length) == sizeof(request));
    assert(memcmp(request, "request", sizeof(request)) == 0);
    assert(source.sin_addr.s_addr == inet_addr("10.0.2.15"));
    assert(source.sin_port != 0);
    assert(close(fd) == 0);
    return 0;
}

static int run_client(const char *port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)strtoul(port, NULL, 10)),
    };
    assert(inet_pton(AF_INET, "10.0.2.15", &server.sin_addr) == 1);
    assert(sendto(fd, "request", 7, 0, (const struct sockaddr *)&server,
                  sizeof(server)) == 7);
    struct sockaddr_in local;
    socklen_t length = sizeof(local);
    assert(getsockname(fd, (struct sockaddr *)&local, &length) == 0);
    assert(local.sin_addr.s_addr == htonl(INADDR_ANY));
    assert(local.sin_port != 0);
    assert(close(fd) == 0);
    return 0;
}

int main(int argc, char **argv) {
    assert(argc >= 2);
    if (strcmp(argv[1], "server") == 0) {
        assert(argc == 2);
        return run_server();
    }
    assert(strcmp(argv[1], "client") == 0);
    assert(argc == 3);
    return run_client(argv[2]);
}
