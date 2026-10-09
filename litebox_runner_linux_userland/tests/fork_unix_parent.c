// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that forked and exec'd children share Unix domain sockets with their parent.

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/fork_unix_parent.sock"
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

// `listener` is nonblocking, so a connection taken by the other process sharing it fails the accept
// rather than blocking it.
static int accept_within(int listener) {
    return wait_readable(listener) ? accept(listener, NULL, NULL) : -1;
}

// Returns the exit code of `child`, or -1 if it did not exit normally.
static int wait_code(pid_t child) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Reaps `child`, first killing it if the parent already failed, since it may be waiting on the
// parent. Returns the failures including one if the child did not exit with `expected`.
static int finish(pid_t child, int failures, int expected) {
    if (failures != 0) {
        kill(child, SIGKILL);
    }
    return failures + (wait_code(child) != expected);
}

// A forked child talks to its parent over an inherited stream socket pair.
static int stream_pair(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        _exit(send_all(pair[1], "ping") && expect(pair[1], "pong") ? 0 : 1);
    }
    close(pair[1]);
    if (child < 0) {
        close(pair[0]);
        return 1;
    }
    int failures = !expect(pair[0], "ping");
    failures += !send_all(pair[0], "pong");
    failures = finish(child, failures, 0);
    // The child's exit closed the only other reference to the peer.
    char byte;
    failures += !wait_readable(pair[0]) || read(pair[0], &byte, 1) != 0;
    close(pair[0]);
    return failures;
}

// A forked child sends a datagram over an inherited datagram socket pair.
static int datagram_pair(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        _exit(send(pair[1], "dgram", 5, 0) == 5 ? 0 : 1);
    }
    close(pair[1]);
    if (child < 0) {
        close(pair[0]);
        return 1;
    }
    char buffer[16] = {0};
    // Closing a datagram peer does not end receives, so the child exits before a nonblocking
    // receive.
    int failures = finish(child, 0, 0);
    failures +=
        recv(pair[0], buffer, sizeof buffer, MSG_DONTWAIT) != 5 || memcmp(buffer, "dgram", 5) != 0;
    close(pair[0]);
    return failures;
}

// A forked child connects to its parent's listener by path, then accepts the parent's connection
// on the listener it inherited.
static int path_listener(void) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strncpy(address.sun_path, SOCKET_PATH, sizeof address.sun_path - 1);
    unlink(SOCKET_PATH);
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(listener, 4) != 0) {
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        int ok = 1;
        struct sockaddr_un name = {0};
        socklen_t length = sizeof name;
        ok &= getsockname(listener, (struct sockaddr *)&name, &length) == 0 &&
              strcmp(name.sun_path, SOCKET_PATH) == 0;
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        ok &= client >= 0 && connect(client, (struct sockaddr *)&address, sizeof address) == 0;
        ok &= send_all(client, "hello") && expect(client, "world");
        int accepted = accept_within(listener);
        ok &= accepted >= 0 && expect(accepted, "parent");
        _exit(ok ? 0 : 1);
    }
    if (child < 0) {
        close(listener);
        unlink(SOCKET_PATH);
        return 1;
    }
    int accepted = accept_within(listener);
    int failures = accepted < 0 || !expect(accepted, "hello") || !send_all(accepted, "world");
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    failures += client < 0 || connect(client, (struct sockaddr *)&address, sizeof address) != 0 ||
                !send_all(client, "parent");
    failures = finish(child, failures, 0);
    close(client);
    close(accepted);
    close(listener);
    unlink(SOCKET_PATH);
    return failures;
}

// An exec'd child keeps an inherited socket but not a close-on-exec one.
static int exec_child(const char *child_path) {
    int pair[2];
    int hidden[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, hidden) != 0) {
        return 1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        char socket_fd[16];
        char hidden_fd[16];
        snprintf(socket_fd, sizeof socket_fd, "%d", pair[1]);
        snprintf(hidden_fd, sizeof hidden_fd, "%d", hidden[0]);
        char *const argv[] = {(char *)child_path, "unix-fd", socket_fd, hidden_fd, NULL};
        execv(child_path, argv);
        _exit(99);
    }
    close(pair[1]);
    close(hidden[0]);
    close(hidden[1]);
    if (child < 0) {
        close(pair[0]);
        return 1;
    }
    int failures = !expect(pair[0], "exec");
    failures += !send_all(pair[0], "reply");
    failures = finish(child, failures, 42);
    close(pair[0]);
    return failures;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    fflush(stdout);
    int stream = stream_pair();
    int datagram = datagram_pair();
    int path = path_listener();
    int exec = exec_child(argv[1]);
    printf("unix-fork stream=%d dgram=%d path=%d exec=%d\n", stream, datagram, path, exec);
    return stream + datagram + path + exec;
}
