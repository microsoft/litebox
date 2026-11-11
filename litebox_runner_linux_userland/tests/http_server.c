// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A minimal HTTP/1.0 server on guest port 8080 that answers one request from a
// host client of a published port (`--publish`), then exits. The response
// body reports the endpoints the guest saw: the guest's own address, and the
// gateway as the peer.

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GUEST_PORT 8080

int main(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    int reuse = 1;
    assert(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse,
                      sizeof(reuse)) == 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(GUEST_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(listener, 8) == 0);

    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    int connection = accept(listener, (struct sockaddr *)&peer, &length);
    assert(connection >= 0);
    assert(length == sizeof(peer));

    struct sockaddr_in local;
    length = sizeof(local);
    assert(getsockname(connection, (struct sockaddr *)&local, &length) == 0);

    char request[1024];
    size_t received = 0;
    while (received < sizeof(request) - 1) {
        ssize_t count =
            recv(connection, request + received, sizeof(request) - 1 - received, 0);
        assert(count > 0);
        received += (size_t)count;
        request[received] = '\0';
        if (strstr(request, "\r\n\r\n") != NULL) {
            break;
        }
    }
    assert(strncmp(request, "GET / HTTP/1.", 13) == 0);

    char peer_ip[INET_ADDRSTRLEN];
    char local_ip[INET_ADDRSTRLEN];
    assert(inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip)));
    assert(inet_ntop(AF_INET, &local.sin_addr, local_ip, sizeof(local_ip)));
    char body[128];
    int body_length = snprintf(body, sizeof(body), "peer %s local %s:%u\n",
                               peer_ip, local_ip, ntohs(local.sin_port));
    char response[256];
    int response_length = snprintf(
        response, sizeof(response),
        "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        body_length, body);
    size_t sent = 0;
    while (sent < (size_t)response_length) {
        // A client that gave up fails the send rather than kill the server.
        ssize_t count = send(connection, response + sent,
                             (size_t)response_length - sent, MSG_NOSIGNAL);
        assert(count > 0);
        sent += (size_t)count;
    }
    assert(shutdown(connection, SHUT_WR) == 0);
    // Wait for the client's close, so the response is not cut off by a reset.
    char byte;
    while (recv(connection, &byte, 1, 0) > 0) {
    }
    close(connection);
    close(listener);
    printf("served %s", body);
    return 0;
}
