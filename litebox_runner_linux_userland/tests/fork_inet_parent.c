// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that forked and exec'd children share IPv4 sockets with their parent.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// Bounds every wait, so a failure cannot hang the test.
#define TIMEOUT_MS 30000

static int wait_readable(int fd) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    int ready;
    do {
        ready = poll(&poll_fd, 1, TIMEOUT_MS);
    } while (ready == -1 && errno == EINTR);
    return ready == 1;
}

static int read_exact(int fd, char *buffer, size_t length) {
    size_t received = 0;
    while (received < length) {
        if (!wait_readable(fd)) {
            return 0;
        }
        ssize_t n = read(fd, buffer + received, length - received);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return 0;
        }
        received += n;
    }
    return 1;
}

static int expect(int fd, const char *message) {
    char buffer[16] = {0};
    size_t length = strlen(message);
    return read_exact(fd, buffer, length) && memcmp(buffer, message, length) == 0;
}

static int send_all(int fd, const char *message) {
    size_t length = strlen(message);
    return write(fd, message, length) == (ssize_t)length;
}

// Returns whether the peer of `fd` closed it.
static int expect_eof(int fd) {
    char byte;
    return wait_readable(fd) && read(fd, &byte, 1) == 0;
}

// `listener` is nonblocking, so a connection taken by the other process sharing it fails the accept
// rather than blocking it.
static int accept_within(int listener) {
    return wait_readable(listener) ? accept(listener, NULL, NULL) : -1;
}

// Returns the exit code of `child`, or of any child if `child` is -1, or -1 if it did not exit
// normally.
static int wait_code(pid_t child) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    if (waited <= 0 || (child > 0 && waited != child) || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

// Reaps `child`, first killing it if the parent already failed, since it may be waiting on the
// parent. Returns the failures including one if the child did not exit with `expected`.
static int finish(pid_t child, int failures, int expected) {
    if (failures != 0) {
        kill(child, SIGKILL);
    }
    return failures + (wait_code(child) != expected);
}

// Creates a socket of `type` bound to an ephemeral loopback port, storing its address in
// `address`.
static int bound_socket(int type, struct sockaddr_in *address) {
    int fd = socket(AF_INET, type, 0);
    struct sockaddr_in loopback = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof *address;
    if (fd < 0 || bind(fd, (struct sockaddr *)&loopback, sizeof loopback) != 0 ||
        getsockname(fd, (struct sockaddr *)address, &length) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    return fd;
}

static int connect_to(const struct sockaddr_in *address) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0 && connect(fd, (const struct sockaddr *)address, sizeof *address) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// A forked child connects to its parent's listener, then accepts the parent's connection on the
// listener it inherited. The listener keeps working after the child exits.
static int tcp_listener(void) {
    struct sockaddr_in address;
    int listener = bound_socket(SOCK_STREAM | SOCK_NONBLOCK, &address);
    if (listener < 0 || listen(listener, 4) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        struct sockaddr_in name = {0};
        socklen_t length = sizeof name;
        int ok = getsockname(listener, (struct sockaddr *)&name, &length) == 0 &&
                 name.sin_port == address.sin_port;
        int client = connect_to(&address);
        ok &= client >= 0 && send_all(client, "hello") && expect(client, "world");
        int accepted = accept_within(listener);
        ok &= accepted >= 0 && expect(accepted, "parent") && send_all(accepted, "child");
        _exit(ok ? 0 : 1);
    }
    if (child < 0) {
        close(listener);
        return 1;
    }
    int accepted = accept_within(listener);
    int failures = accepted < 0 || !expect(accepted, "hello") || !send_all(accepted, "world");
    int client = connect_to(&address);
    failures += client < 0 || !send_all(client, "parent") || !expect(client, "child");
    failures = finish(child, failures, 0);
    // The child's exit closed its connection and its socket accepted from the shared listener.
    failures += !expect_eof(accepted) || !expect_eof(client);
    close(client);
    close(accepted);
    int again = connect_to(&address);
    int reaccepted = accept_within(listener);
    failures += again < 0 || reaccepted < 0 || !send_all(again, "again") ||
                !expect(reaccepted, "again");
    close(reaccepted);
    close(again);
    close(listener);
    return failures;
}

// A forked child receives on an inherited bound datagram socket and replies from it, so the reply
// comes from the parent's address.
static int udp_shared(void) {
    struct sockaddr_in shared_address;
    struct sockaddr_in peer_address;
    int shared = bound_socket(SOCK_DGRAM, &shared_address);
    int peer = bound_socket(SOCK_DGRAM, &peer_address);
    if (shared < 0 || peer < 0) {
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(peer);
        char buffer[16] = {0};
        int ok = wait_readable(shared) && recv(shared, buffer, sizeof buffer, 0) == 4 &&
                 memcmp(buffer, "ping", 4) == 0;
        ok &= sendto(shared, "pong", 4, 0, (struct sockaddr *)&peer_address, sizeof peer_address) ==
              4;
        _exit(ok ? 0 : 1);
    }
    if (child < 0) {
        close(shared);
        close(peer);
        return 1;
    }
    int failures = sendto(peer, "ping", 4, 0, (struct sockaddr *)&shared_address,
                          sizeof shared_address) != 4;
    char buffer[16] = {0};
    struct sockaddr_in source = {0};
    socklen_t length = sizeof source;
    failures += !wait_readable(peer) ||
                recvfrom(peer, buffer, sizeof buffer, 0, (struct sockaddr *)&source, &length) != 4 ||
                memcmp(buffer, "pong", 4) != 0 || source.sin_port != shared_address.sin_port;
    failures = finish(child, failures, 0);
    close(shared);
    close(peer);
    return failures;
}

// A forked child connects a socket and passes it to a grandchild, which keeps using it after the
// child that created it exits.
static int orphaned_socket(void) {
    struct sockaddr_in address;
    int listener = bound_socket(SOCK_STREAM | SOCK_NONBLOCK, &address);
    if (listener < 0 || listen(listener, 4) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(listener);
        int client = connect_to(&address);
        if (client < 0) {
            _exit(1);
        }
        pid_t grandchild = fork();
        if (grandchild == 0) {
            _exit(expect(client, "go") && send_all(client, "orphan") ? 0 : 1);
        }
        _exit(grandchild < 0);
    }
    if (child < 0) {
        close(listener);
        return 1;
    }
    int accepted = accept_within(listener);
    int failures = finish(child, accepted < 0, 0);
    failures += accepted < 0 || !send_all(accepted, "go") || !expect(accepted, "orphan");
    failures += accepted < 0 || !expect_eof(accepted);
    // The initial process adopts the orphaned grandchild.
    failures += wait_code(-1) != 0;
    close(accepted);
    close(listener);
    return failures;
}

// An exec'd child keeps an inherited socket but not a close-on-exec one.
static int exec_child(const char *child_path) {
    struct sockaddr_in address;
    int listener = bound_socket(SOCK_STREAM, &address);
    if (listener < 0 || listen(listener, 1) != 0) {
        return 1;
    }
    int client = connect_to(&address);
    int accepted = client < 0 ? -1 : accept(listener, NULL, NULL);
    int hidden = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    close(listener);
    if (client < 0 || accepted < 0 || hidden < 0) {
        return 1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(accepted);
        char socket_fd[16];
        char hidden_fd[16];
        snprintf(socket_fd, sizeof socket_fd, "%d", client);
        snprintf(hidden_fd, sizeof hidden_fd, "%d", hidden);
        char *const argv[] = {(char *)child_path, "inet-fd", socket_fd, hidden_fd, NULL};
        execv(child_path, argv);
        _exit(99);
    }
    close(client);
    close(hidden);
    if (child < 0) {
        close(accepted);
        return 1;
    }
    int failures = !expect(accepted, "exec");
    failures += !send_all(accepted, "reply");
    failures = finish(child, failures, 42);
    close(accepted);
    return failures;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    fflush(stdout);
    int tcp = tcp_listener();
    int udp = udp_shared();
    int orphan = orphaned_socket();
    int exec = exec_child(argv[1]);
    printf("inet-fork tcp=%d udp=%d orphan=%d exec=%d\n", tcp, udp, orphan, exec);
    return tcp + udp + orphan + exec;
}
