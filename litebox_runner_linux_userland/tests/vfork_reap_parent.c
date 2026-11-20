// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Ignoring `SIGCHLD`, or setting `SA_NOCLDWAIT`, has vfork children reaped automatically, including
// live ones when the disposition changes; a program started with `SIGCHLD` ignored keeps it, while
// `execve` clears `SA_NOCLDWAIT`.

#define _GNU_SOURCE
#include "helpers.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *child_path;

static void set_sigchld(void (*handler)(int), int flags) {
    struct sigaction action = {.sa_handler = handler, .sa_flags = flags};
    if (sigaction(SIGCHLD, &action, NULL) != 0) {
        perror("sigaction");
        _exit(3);
    }
}

static pid_t spawn_exit(int code) {
    pid_t child = vfork();
    if (child == 0) {
        _exit(code);
    }
    if (child < 0) {
        perror("vfork");
        _exit(4);
    }
    return child;
}

static pid_t spawn_exec(const char *mode, const char *arg) {
    pid_t child = vfork();
    if (child == 0) {
        execl(child_path, child_path, mode, arg, (char *)NULL);
        _exit(111);
    }
    if (child < 0) {
        perror("vfork");
        _exit(5);
    }
    return child;
}

// The exec'd child exits with code 42 once `gate` exists, so it stays live until the parent
// calls `open_gate`.
static pid_t spawn_gated(const char *gate) {
    unlink(gate);
    return spawn_exec("gate", gate);
}

static void open_gate(const char *gate) {
    int fd = open(gate, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        perror("open gate");
        _exit(6);
    }
    close(fd);
}

static int echild(pid_t pid) {
    return waitpid(pid, NULL, 0) == -1 && errno == ECHILD;
}

// Starts the child with `mode`, its stdout a pipe this process reads, as its exit code may be reaped
// automatically, and returns whether it reported exactly `expected`. The caller reaps the child, if
// it can be reaped.
static int spawn_reporting(const char *mode, const char *expected) {
    int out[2];
    if (pipe(out) != 0) {
        perror("pipe");
        _exit(7);
    }
    fflush(stdout);
    pid_t child = vfork();
    if (child == 0) {
        if (dup2(out[1], 1) == 1) {
            execl(child_path, child_path, mode, (char *)NULL);
        }
        _exit(111);
    }
    if (child < 0) {
        perror("vfork");
        _exit(5);
    }
    close(out[1]);
    char report[128];
    size_t length = 0;
    ssize_t n;
    while (length < sizeof report - 1 &&
           (n = read(out[0], report + length, sizeof report - 1 - length)) > 0) {
        length += n;
    }
    report[length] = '\0';
    close(out[0]);
    printf("%s", report);
    return strcmp(report, expected) == 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }
    child_path = argv[1];

    // A zombie from before SIGCHLD is ignored stays waitable. Linux resumes a vfork parent
    // before the child finishes exiting, so give the child time to become a zombie.
    pid_t zombie = spawn_exit(21);
    usleep(100 * 1000);
    set_sigchld(SIG_IGN, 0);
    int status = 0;
    pid_t waited = waitpid(zombie, &status, 0);
    printf("zombie child=%d waited=%d exited=%d code=%d\n", zombie, waited,
           WIFEXITED(status), WEXITSTATUS(status));
    int failures = waited != zombie || !WIFEXITED(status) || WEXITSTATUS(status) != 21;

    // Blocking waits return once the children are reaped.
    pid_t ignored = spawn_exit(22);
    int reaped = echild(ignored);
    printf("ignored echild=%d\n", reaped);
    failures += !reaped;

    set_sigchld(SIG_DFL, SA_NOCLDWAIT);
    spawn_exit(23);
    reaped = echild(-1);
    printf("nocldwait echild=%d\n", reaped);
    failures += !reaped;

    // A live child follows a later disposition change.
    char *ignored_gate = test_path("vfork_reap_ignored");
    char *restored_gate = test_path("vfork_reap_restored");
    set_sigchld(SIG_DFL, 0);
    spawn_gated(ignored_gate);
    set_sigchld(SIG_IGN, 0);
    open_gate(ignored_gate);
    reaped = echild(-1);
    printf("live-ignored echild=%d\n", reaped);
    failures += !reaped;

    pid_t restored = spawn_gated(restored_gate);
    set_sigchld(SIG_DFL, 0);
    open_gate(restored_gate);
    status = 0;
    waited = waitpid(restored, &status, 0);
    printf("live-restored child=%d waited=%d exited=%d code=%d\n", restored, waited,
           WIFEXITED(status), WEXITSTATUS(status));
    failures += waited != restored || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
    unlink(ignored_gate);
    unlink(restored_gate);

    // A program started while SIGCHLD is ignored keeps reaping its children.
    set_sigchld(SIG_IGN, 0);
    failures += !spawn_reporting("reap-inherited", "reap-inherited reaped=1\n");
    echild(-1);
    set_sigchld(SIG_DFL, 0);

    // Exec clears SA_NOCLDWAIT, so the new program's children are waitable.
    failures += !spawn_reporting("reap-nocldwait", "reap-reset reaped=0\n");
    wait(NULL);
    printf("vfork-reap failures=%d\n", failures);
    return failures != 0;
}
