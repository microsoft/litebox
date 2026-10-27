// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that sessions acquire pseudo-terminals as controlling terminals, which signal them and
// hang up, across forked and vforked children.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int failures;
static volatile sig_atomic_t received;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static void on_signal(int signal) { received = signal; }

// Handles `SIGINT` and `SIGHUP` by recording them.
static int handle_signals(void) {
    struct sigaction action = {.sa_handler = on_signal};
    return sigaction(SIGINT, &action, NULL) == 0 && sigaction(SIGHUP, &action, NULL) == 0;
}

// Returns whether `signal` is handled within five seconds.
static int wait_for(int signal) {
    const struct timespec delay = {.tv_nsec = 1000000};
    for (int i = 0; i < 5000 && received != signal; i++) {
        nanosleep(&delay, NULL);
    }
    return received == signal;
}

// Reaps child `pid`, returning its exit code, or -1 if it did not exit.
static int reap(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

// Returns whether `fd` yields exactly `expected`, which the line discipline may split.
static int read_exactly(int fd, const char *expected) {
    char buffer[64];
    size_t length = strlen(expected), received_length = 0;
    while (received_length < length) {
        ssize_t size = read(fd, buffer + received_length, length - received_length);
        if (size <= 0) {
            return 0;
        }
        received_length += (size_t)size;
    }
    return memcmp(buffer, expected, length) == 0;
}

static int signal_byte(int fd) {
    char byte = 0;
    return write(fd, &byte, 1) == 1;
}

static int await_byte(int fd) {
    char byte;
    return read(fd, &byte, 1) == 1;
}

// A session leader acquires a terminal with `TIOCSCTTY`, which then interrupts it and hangs up
// when its manager closes.
static void set_controlling_terminal(void) {
    int manager, subsidiary;
    CHECK(openpty(&manager, &subsidiary, NULL, NULL, NULL) == 0);
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t leader = fork();
    if (leader == 0) {
        close(manager);
        close(ready[0]);
        int ok = handle_signals();
        ok = ok && ioctl(subsidiary, TIOCSCTTY, 0) == -1 && errno == EPERM;
        ok = ok && setsid() == getpid();
        ok = ok && open("/dev/tty", O_RDWR) == -1 && errno == ENXIO;
        ok = ok && ioctl(subsidiary, TIOCSCTTY, 0) == 0 && ioctl(subsidiary, TIOCSCTTY, 0) == 0;
        ok = ok && tcgetpgrp(subsidiary) == getpid() && tcgetsid(subsidiary) == getpid();
        int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
        ok = ok && tty >= 0 && write(tty, "via tty\n", 8) == 8;
        ok = ok && signal_byte(ready[1]) && wait_for(SIGINT);
        ok = ok && signal_byte(ready[1]) && wait_for(SIGHUP);
        _exit(ok ? 10 : 11);
    }
    close(ready[1]);
    CHECK(await_byte(ready[0]));
    // Another session's subsidiary reaches no controlling terminal.
    CHECK(tcgetpgrp(subsidiary) == -1 && errno == ENOTTY);
    CHECK(ioctl(subsidiary, TIOCSCTTY, 0) == -1 && errno == EPERM);
    // Manager reads end once the leader exits, should it fail.
    close(subsidiary);
    CHECK(read_exactly(manager, "via tty\r\n"));
    // The manager reaches the terminal's session.
    CHECK(tcgetpgrp(manager) == leader && tcgetsid(manager) == leader);
    CHECK(write(manager, "\x03", 1) == 1);
    CHECK(await_byte(ready[0]));
    close(manager);
    CHECK(reap(leader) == 10);
    close(ready[0]);
}

// A session leader acquires a terminal it opens for reading, and its foreground group hears it
// exit.
static void open_controlling_terminal(void) {
    int manager, subsidiary;
    char name[64];
    CHECK(openpty(&manager, &subsidiary, name, NULL, NULL) == 0);
    close(subsidiary);
    int heard[2], reaped[2];
    CHECK(pipe(heard) == 0 && pipe(reaped) == 0);
    pid_t leader = fork();
    if (leader == 0) {
        close(manager);
        close(heard[0]);
        close(reaped[1]);
        int ok = setsid() == getpid();
        int write_only = open(name, O_WRONLY);
        ok = ok && write_only >= 0 && tcgetpgrp(write_only) == -1 && errno == ENOTTY;
        int terminal = open(name, O_RDWR);
        ok = ok && terminal >= 0 && tcgetpgrp(terminal) == getpid();
        int ready[2] = {-1, -1};
        ok = ok && pipe(ready) == 0;
        pid_t member = fork();
        if (member == 0) {
            close(ready[0]);
            int heard_ok = handle_signals() && signal_byte(ready[1]) && wait_for(SIGHUP);
            // Linux signals the foreground group before the session loses its terminal, which it
            // has once the leader is reaped.
            heard_ok = heard_ok && await_byte(reaped[0]);
            heard_ok = heard_ok && open("/dev/tty", O_RDWR) == -1 && errno == ENXIO;
            heard_ok = heard_ok && tcgetpgrp(terminal) == -1 && errno == ENOTTY;
            char result = heard_ok ? 'y' : 'n';
            _exit(write(heard[1], &result, 1) == 1 ? 0 : 1);
        }
        close(ready[1]);
        _exit(ok && member > 0 && await_byte(ready[0]) ? 20 : 21);
    }
    close(heard[1]);
    close(reaped[0]);
    CHECK(reap(leader) == 20);
    CHECK(signal_byte(reaped[1]));
    char result = 0;
    CHECK(read(heard[0], &result, 1) == 1 && result == 'y');
    close(manager);
    close(heard[0]);
    close(reaped[1]);
}

// A vforked child's open leaves the parent's session alone, while it can acquire a terminal for
// its own session.
static void vfork_controlling_terminal(void) {
    int manager, subsidiary;
    char name[64];
    CHECK(openpty(&manager, &subsidiary, name, NULL, NULL) == 0);
    pid_t opener = vfork();
    if (opener == 0) {
        _exit(open(name, O_RDWR) >= 0 ? 30 : 31);
    }
    CHECK(reap(opener) == 30);
    CHECK(tcgetpgrp(subsidiary) == -1 && errno == ENOTTY);
    pid_t leader = vfork();
    if (leader == 0) {
        _exit(setsid() == getpid() && ioctl(subsidiary, TIOCSCTTY, 1) == 0 ? 32 : 33);
    }
    CHECK(reap(leader) == 32);
    close(manager);
    close(subsidiary);
}

int main(void) {
    set_controlling_terminal();
    open_controlling_terminal();
    vfork_controlling_terminal();
    printf("ctty failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
