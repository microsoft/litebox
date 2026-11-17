// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Booted as litebox.init with egress.policy.txt, which allows TCP to
// 10.0.2.100:7 only: checks that a connection there echoes, and that TCP to
// another port and UDP fail with EACCES.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
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

static void allowed(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_in server = address("10.0.2.100", 7);
    CHECK(connect(fd, (struct sockaddr *)&server, sizeof(server)) == 0);
    CHECK(write(fd, "ping", 4) == 4);
    char buffer[4];
    size_t done = 0;
    while (done < sizeof(buffer)) {
        ssize_t n = read(fd, buffer + done, sizeof(buffer) - done);
        CHECK(n > 0);
        done += (size_t)n;
    }
    CHECK(memcmp(buffer, "ping", 4) == 0);
    CHECK(close(fd) == 0);
    printf("tcp 10.0.2.100:7 allowed: ok\n");
}

static void denied(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_in server = address("10.0.2.100", 8);
    CHECK(connect(fd, (struct sockaddr *)&server, sizeof(server)) == -1 && errno == EACCES);
    CHECK(close(fd) == 0);
    printf("tcp 10.0.2.100:8 denied: ok\n");

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    server = address("10.0.2.100", 7);
    CHECK(sendto(fd, "ping", 4, 0, (struct sockaddr *)&server, sizeof(server)) == -1 &&
          errno == EACCES);
    CHECK(close(fd) == 0);
    printf("udp 10.0.2.100:7 denied: ok\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    allowed();
    denied();
    return 0;
}
