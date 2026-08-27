// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void assert_file_contents(const char *path, const char *expected) {
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    char contents[256];
    size_t length = fread(contents, 1, sizeof(contents), file);
    assert(!ferror(file));
    assert(feof(file));
    assert(length == strlen(expected));
    assert(memcmp(contents, expected, length) == 0);
    assert(fclose(file) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char *end = NULL;
    unsigned long port = strtoul(argv[1], &end, 10);
    assert(end != argv[1] && *end == '\0' && port > 0 && port <= UINT16_MAX);

    assert_file_contents(
        "/etc/resolv.conf",
        "nameserver 10.0.2.3\noptions timeout:1 attempts:2\n");
    assert_file_contents(
        "/etc/hosts",
        "127.0.0.1 localhost\n::1 localhost\n127.0.0.1 litebox\n");

    FILE *nsswitch = fopen("/etc/nsswitch.conf", "r");
    assert(nsswitch != NULL);
    char nsswitch_line[256];
    size_t generated_hosts_entries = 0;
    while (fgets(nsswitch_line, sizeof(nsswitch_line), nsswitch) != NULL) {
        generated_hosts_entries +=
            strcmp(nsswitch_line, "hosts: files dns\n") == 0;
    }
    assert(feof(nsswitch));
    assert(generated_hosts_entries == 1);
    assert(fclose(nsswitch) == 0);

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };
    struct addrinfo *addresses = NULL;
    int resolve_result =
        getaddrinfo("service.example", NULL, &hints, &addresses);
    if (resolve_result != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(resolve_result));
    }
    assert(resolve_result == 0);
    assert(addresses != NULL);
    assert(addresses->ai_family == AF_INET);
    assert(addresses->ai_addrlen == sizeof(struct sockaddr_in));

    struct sockaddr_in destination =
        *(const struct sockaddr_in *)addresses->ai_addr;
    freeaddrinfo(addresses);
    assert(destination.sin_addr.s_addr == inet_addr("198.51.100.1"));
    destination.sin_port = htons((uint16_t)port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    assert(connect(fd, (const struct sockaddr *)&destination,
                   sizeof(destination)) == 0);
    const char request[] = "dns-pinned request";
    assert(write(fd, request, sizeof(request)) == sizeof(request));
    assert(close(fd) == 0);
    return 0;
}
