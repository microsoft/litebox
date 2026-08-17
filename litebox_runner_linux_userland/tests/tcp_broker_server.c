// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static void verify_endpoints(int fd, const struct sockaddr_in *local,
                             const struct sockaddr_in *accepted_peer) {
    struct sockaddr_in actual_local;
    socklen_t length = sizeof(actual_local);
    assert(getsockname(fd, (struct sockaddr *)&actual_local, &length) == 0);
    assert(length == sizeof(actual_local));
    assert(actual_local.sin_family == AF_INET);
    assert(actual_local.sin_addr.s_addr == local->sin_addr.s_addr);
    assert(actual_local.sin_port == local->sin_port);

    struct sockaddr_in actual_peer;
    length = sizeof(actual_peer);
    assert(getpeername(fd, (struct sockaddr *)&actual_peer, &length) == 0);
    assert(length == sizeof(actual_peer));
    assert(actual_peer.sin_family == AF_INET);
    assert(actual_peer.sin_addr.s_addr == accepted_peer->sin_addr.s_addr);
    assert(actual_peer.sin_port == accepted_peer->sin_port);
}

static void exchange_byte(int fd, unsigned char expected,
                          unsigned char response) {
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    assert(poll(&ready, 1, 5000) == 1);
    assert((ready.revents & POLLIN) != 0);
    unsigned char byte = 0;
    assert(read(fd, &byte, sizeof(byte)) == sizeof(byte));
    assert(byte == expected);
    assert(write(fd, &response, sizeof(response)) == sizeof(response));
}

struct blocking_accept {
    int fd;
    int result;
    int error;
};

struct client_exchange {
    struct sockaddr_in server;
    struct sockaddr_in local;
    unsigned char request;
    unsigned char expected_response;
};

static void *blocking_accept_thread(void *argument) {
    struct blocking_accept *accept = argument;
    errno = 0;
    accept->result = accept4(accept->fd, NULL, NULL, 0);
    accept->error = errno;
    return NULL;
}

static void *client_exchange_thread(void *argument) {
    struct client_exchange *exchange = argument;
    usleep(100 * 1000);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    assert(connect(fd, (const struct sockaddr *)&exchange->server,
                   sizeof(exchange->server)) == 0);
    socklen_t length = sizeof(exchange->local);
    assert(getsockname(fd, (struct sockaddr *)&exchange->local, &length) == 0);
    assert(length == sizeof(exchange->local));
    assert(write(fd, &exchange->request, sizeof(exchange->request)) ==
           sizeof(exchange->request));
    unsigned char response = 0;
    assert(read(fd, &response, sizeof(response)) == sizeof(response));
    assert(response == exchange->expected_response);
    assert(close(fd) == 0);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    int listener =
        socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    assert(listener >= 0);
    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = 0,
    };
    assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
    assert(bind(listener, (const struct sockaddr *)&local, sizeof(local)) == 0);
    assert(listen(listener, 8) == 0);
    assert(shutdown(listener, SHUT_WR) == 0);
    socklen_t length = sizeof(local);
    assert(getsockname(listener, (struct sockaddr *)&local, &length) == 0);
    assert(length == sizeof(local));
    assert(local.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(local.sin_port != 0);

    assert(accept(listener, NULL, NULL) == -1);
    assert(errno == EAGAIN);
    printf("LISTEN %u\n", (unsigned int)ntohs(local.sin_port));

    int first_client = socket(AF_INET, SOCK_STREAM, 0);
    assert(first_client >= 0);
    assert(connect(first_client, (const struct sockaddr *)&local, sizeof(local)) ==
           0);
    struct sockaddr_in first_client_local;
    length = sizeof(first_client_local);
    assert(getsockname(first_client, (struct sockaddr *)&first_client_local,
                       &length) == 0);
    assert(length == sizeof(first_client_local));
    unsigned char first_request = 0x31;
    assert(write(first_client, &first_request, sizeof(first_request)) ==
           sizeof(first_request));

    struct pollfd ready = {.fd = listener, .events = POLLIN};
    assert(poll(&ready, 1, 5000) == 1);
    assert((ready.revents & POLLIN) != 0);
    struct sockaddr_in first_peer;
    length = sizeof(first_peer);
    int first = accept4(listener, (struct sockaddr *)&first_peer, &length,
                        SOCK_NONBLOCK | SOCK_CLOEXEC);
    assert(first >= 0);
    assert(length == sizeof(first_peer));
    assert((fcntl(first, F_GETFL) & O_NONBLOCK) != 0);
    assert((fcntl(first, F_GETFD) & FD_CLOEXEC) != 0);
    verify_endpoints(first, &local, &first_peer);
    exchange_byte(first, 0x31, 0x41);
    unsigned char first_response = 0;
    assert(read(first_client, &first_response, sizeof(first_response)) ==
           sizeof(first_response));
    assert(first_response == 0x41);
    assert(first_peer.sin_addr.s_addr == first_client_local.sin_addr.s_addr);
    assert(first_peer.sin_port == first_client_local.sin_port);
    assert(close(first_client) == 0);
    printf("FIRST %u\n", (unsigned int)ntohs(first_peer.sin_port));

    int listener_flags = fcntl(listener, F_GETFL);
    assert(listener_flags >= 0);
    assert(fcntl(listener, F_SETFL, listener_flags & ~O_NONBLOCK) == 0);
    printf("BLOCKING\n");

    struct client_exchange second_exchange = {
        .server = local,
        .request = 0x32,
        .expected_response = 0x42,
    };
    pthread_t client_thread;
    assert(pthread_create(&client_thread, NULL, client_exchange_thread,
                          &second_exchange) == 0);
    struct sockaddr_in second_peer;
    length = sizeof(second_peer);
    int second =
        accept(listener, (struct sockaddr *)&second_peer, &length);
    assert(second >= 0);
    assert(length == sizeof(second_peer));
    assert((fcntl(second, F_GETFL) & O_NONBLOCK) == 0);
    assert((fcntl(second, F_GETFD) & FD_CLOEXEC) == 0);
    verify_endpoints(second, &local, &second_peer);
    exchange_byte(second, 0x32, 0x42);
    assert(pthread_join(client_thread, NULL) == 0);
    assert(second_peer.sin_addr.s_addr ==
           second_exchange.local.sin_addr.s_addr);
    assert(second_peer.sin_port == second_exchange.local.sin_port);
    printf("SECOND %u\n", (unsigned int)ntohs(second_peer.sin_port));

    struct blocking_accept accept = {
        .fd = listener,
        .result = 0,
        .error = 0,
    };
    pthread_t accept_thread;
    assert(pthread_create(&accept_thread, NULL, blocking_accept_thread, &accept) ==
           0);
    usleep(100 * 1000);
    assert(shutdown(listener, SHUT_RDWR) == 0);
    assert(pthread_join(accept_thread, NULL) == 0);
    assert(accept.result == -1);
    assert(accept.error == EINVAL);
    ready.events = POLLIN;
    ready.revents = 0;
    assert(poll(&ready, 1, 0) == 1);
    assert((ready.revents & POLLHUP) != 0);

    assert(close(first) == 0);
    assert(close(second) == 0);
    assert(close(listener) == 0);
    return 0;
}
