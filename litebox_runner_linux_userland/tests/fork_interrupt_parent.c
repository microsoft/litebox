// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;

static void on_interrupt(int signal) {
    (void)signal;
    interrupted = 1;
}

static void on_timeout(int signal) {
    (void)signal;
    _exit(2);
}

int main(void) {
    int ready[2];
    if (pipe(ready) != 0 || signal(SIGUSR1, on_interrupt) == SIG_ERR ||
        signal(SIGALRM, on_timeout) == SIG_ERR) {
        perror("setup");
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        close(ready[0]);
        alarm(5);
        if (write(ready[1], "x", 1) != 1) {
            _exit(3);
        }
        // No guest syscall can pick up the pending signal: the host must interrupt this loop.
        while (!interrupted) {
        }
        alarm(0);
        _exit(0);
    }
    close(ready[1]);
    char byte;
    ssize_t count;
    do {
        count = read(ready[0], &byte, 1);
    } while (count < 0 && errno == EINTR);
    close(ready[0]);
    if (count != 1 || byte != 'x') {
        return 1;
    }
    // Let the child leave its readiness syscall and enter the CPU-bound loop.
    struct timespec delay = {.tv_nsec = 50 * 1000 * 1000};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
    if (kill(child, SIGUSR1) != 0) {
        perror("kill");
        return 1;
    }
    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "forked child was not interrupted\n");
        return 1;
    }
    puts("forked child interrupted");
    return 0;
}
