// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int disposition_is(int signal, void (*handler)(int)) {
    struct sigaction action;
    return sigaction(signal, NULL, &action) == 0 && action.sa_handler == handler;
}

// Returns whether a child exiting with `code` is reaped automatically instead of being waitable.
static int child_is_reaped(int code) {
    pid_t child = vfork();
    if (child == 0) {
        _exit(code);
    }
    if (child < 0) {
        perror("vfork");
        exit(4);
    }
    return waitpid(child, NULL, 0) == -1 && errno == ECHILD;
}

int main(int argc, char **argv) {
    const char *marker = argc > 1 ? argv[1] : "";
    if (strcmp(marker, "abort") == 0) {
        abort();
    }
    if (strcmp(marker, "gate") == 0 && argc > 2) {
        while (access(argv[2], F_OK) != 0) {
            usleep(1000);
        }
        return 42;
    }
    if (strcmp(marker, "reap-inherited") == 0) {
        printf("reap-inherited reaped=%d\n", child_is_reaped(24));
        return 42;
    }
    if (strcmp(marker, "reap-nocldwait") == 0) {
        struct sigaction action = {.sa_handler = SIG_DFL, .sa_flags = SA_NOCLDWAIT};
        if (sigaction(SIGCHLD, &action, NULL) != 0) {
            perror("sigaction");
            return 3;
        }
        execl(argv[0], argv[0], "reap-reset", (char *)NULL);
        perror("execl");
        return 5;
    }
    if (strcmp(marker, "reap-reset") == 0) {
        printf("reap-reset reaped=%d\n", child_is_reaped(25));
        return 42;
    }
    if (strcmp(marker, "signals") == 0) {
        sigset_t blocked;
        sigprocmask(SIG_BLOCK, NULL, &blocked);
        printf("child-signals pipe_ignored=%d hup_ignored=%d usr2_default=%d "
               "ill_default=%d term_blocked=%d usr2_blocked=%d\n",
               disposition_is(SIGPIPE, SIG_IGN), disposition_is(SIGHUP, SIG_IGN),
               disposition_is(SIGUSR2, SIG_DFL), disposition_is(SIGILL, SIG_DFL),
               sigismember(&blocked, SIGTERM), sigismember(&blocked, SIGUSR2));
        return 42;
    }
    if (strcmp(marker, "fds") == 0 && argc > 4) {
        int log = atoi(argv[2]);
        int stdin_alias = atoi(argv[3]);
        int hidden = atoi(argv[4]);
        printf("child-fds via-stdout\n");
        fflush(stdout);
        dprintf(log, "child-fds via-log\n");
        int stdin_flags = fcntl(stdin_alias, F_GETFL);
        int stdin_setfl = stdin_flags >= 0 && fcntl(stdin_alias, F_SETFL, stdin_flags) == 0;
        int hidden_closed = fcntl(hidden, F_GETFD) == -1 && errno == EBADF;
        printf("child-fds stdin_setfl=%d hidden_closed=%d\n", stdin_setfl, hidden_closed);
        return 42;
    }
    const char *environment = getenv("VFORK_EXEC_TEST");
    printf("child pid=%d ppid=%d tid=%ld marker=%s env=%s\n", getpid(),
           getppid(), syscall(SYS_gettid), marker,
           environment == NULL ? "" : environment);
    return 42;
}
