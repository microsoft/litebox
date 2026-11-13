// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#include "helpers.h"

static volatile sig_atomic_t interrupted;

static void on_alarm(int signal) {
    (void)signal;
    interrupted = 1;
}

static void on_timeout(int signal) {
    (void)signal;
    _exit(2);
}

static void send_message(int fd, char message) {
    TEST_ASSERT(write(fd, &message, 1) == 1, "write handshake");
}

static void expect_message(int fd, char expected) {
    char message = 0;
    ssize_t count;
    do {
        count = read(fd, &message, 1);
    } while (count == -1 && errno == EINTR);
    TEST_ASSERT(count == 1 && message == expected, "read handshake");
}

static void expect_conflict(int fd, int operation) {
    errno = 0;
    TEST_ASSERT(flock(fd, operation | LOCK_NB) == -1 && errno == EWOULDBLOCK,
                "separate open must conflict");
}

static void child_checks(const char *path, int inherited, int request, int reply) {
    alarm(30);
    TEST_ASSERT(flock(inherited, LOCK_EX | LOCK_NB) == 0, "relock inherited description");
    int fresh = open(path, O_RDONLY);
    TEST_ASSERT(fresh >= 0, "child fresh open");
    expect_conflict(fresh, LOCK_EX);
    expect_conflict(fresh, LOCK_SH);
    send_message(reply, 'i');

    expect_message(request, 's');
    TEST_ASSERT(flock(fresh, LOCK_SH | LOCK_NB) == 0, "independent shared lock");
    int other = open(path, O_RDONLY);
    TEST_ASSERT(other >= 0, "second child open");
    expect_conflict(other, LOCK_EX);
    TEST_ASSERT(close(other) == 0, "close unlocked description");
    send_message(reply, 's');

    expect_message(request, 'u');
    TEST_ASSERT(flock(fresh, LOCK_UN) == 0, "unlock child shared lock");
    TEST_ASSERT(close(inherited) == 0, "close inherited description");
    send_message(reply, 'u');

    expect_message(request, 'b');
    expect_conflict(fresh, LOCK_EX);
    send_message(reply, 'b');
    TEST_ASSERT(flock(fresh, LOCK_EX) == 0, "blocking exclusive lock after parent unlock");
    int alias = dup(fresh);
    TEST_ASSERT(alias >= 0 && close(fresh) == 0, "keep lock through duplicated description");
    send_message(reply, 'a');
    expect_message(request, 'c');
    TEST_ASSERT(close(alias) == 0, "final close releases lock");
    send_message(reply, 'c');

    expect_message(request, 't');
    fresh = open(path, O_RDONLY);
    TEST_ASSERT(fresh >= 0, "open for interruptible lock");
    set_handler(SIGALRM, on_alarm, 0); // Deliberately omit SA_RESTART.
    alarm(1);
    send_message(reply, 't');
    errno = 0;
    TEST_ASSERT(flock(fresh, LOCK_EX) == -1 && errno == EINTR && interrupted,
                "SIGALRM interrupts blocking flock");
    alarm(0);
    set_handler(SIGALRM, on_timeout, 0);
    alarm(30);
    send_message(reply, 't');

    expect_message(request, 'e');
    TEST_ASSERT(flock(fresh, LOCK_EX | LOCK_NB) == 0, "fresh exclusive lock before exit");
    send_message(reply, 'e');
    // Leave the fresh description open: process exit must release its lock.
    _exit(0);
}

int main(int argc, char **argv) {
    TEST_ASSERT(argc == 2, "expected lock file path");
    set_handler(SIGALRM, on_timeout, 0);
    alarm(30);
    int fd = open(argv[1], O_RDONLY);
    TEST_ASSERT(fd >= 0, "parent open");
    TEST_ASSERT(flock(fd, LOCK_EX | LOCK_NB) == 0, "parent exclusive lock");
    int request[2], reply[2];
    TEST_ASSERT(pipe(request) == 0 && pipe(reply) == 0, "handshake pipes");
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork");
    if (child == 0) {
        close(request[1]);
        close(reply[0]);
        child_checks(argv[1], fd, request[0], reply[1]);
    }
    close(request[0]);
    close(reply[1]);
    expect_message(reply[0], 'i');
    TEST_ASSERT(flock(fd, LOCK_UN) == 0 && flock(fd, LOCK_SH | LOCK_NB) == 0,
                "parent changes exclusive to shared");
    send_message(request[1], 's');
    expect_message(reply[0], 's');
    TEST_ASSERT(flock(fd, LOCK_UN) == 0, "parent unlocks shared lock");
    expect_conflict(fd, LOCK_EX);
    send_message(request[1], 'u');
    expect_message(reply[0], 'u');
    TEST_ASSERT(flock(fd, LOCK_EX | LOCK_NB) == 0, "parent locks before blocking child");
    send_message(request[1], 'b');
    expect_message(reply[0], 'b');
    // The child has observed contention. It must not report acquisition while we hold the lock.
    struct pollfd pending = {.fd = reply[0], .events = POLLIN};
    TEST_ASSERT(poll(&pending, 1, 100) == 0, "child must wait for parent unlock");
    TEST_ASSERT(flock(fd, LOCK_UN) == 0, "parent releases blocking child");
    expect_message(reply[0], 'a');
    expect_conflict(fd, LOCK_EX);
    send_message(request[1], 'c');
    expect_message(reply[0], 'c');
    TEST_ASSERT(flock(fd, LOCK_EX | LOCK_NB) == 0, "lock available after final close");

    send_message(request[1], 't');
    expect_message(reply[0], 't');
    expect_message(reply[0], 't');
    TEST_ASSERT(flock(fd, LOCK_UN) == 0, "release lock after child EINTR");
    send_message(request[1], 'e');
    expect_message(reply[0], 'e');
    TEST_ASSERT(reap(child, 1) == 0, "child exited successfully");
    TEST_ASSERT(flock(fd, LOCK_EX | LOCK_NB) == 0, "lock available after child exit");
    TEST_ASSERT(close(fd) == 0, "parent final close");
    close(request[1]);
    close(reply[0]);
    alarm(0);
    puts("flock-fork inherited=1 conflict=1 shared=1 blocked=1 close=1 interrupted=1 exit=1");
    return 0;
}
