// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int disposition_is(int signal, void (*handler)(int)) {
    struct sigaction action;
    return sigaction(signal, NULL, &action) == 0 && action.sa_handler == handler;
}

int main(int argc, char **argv) {
    const char *marker = argc > 1 ? argv[1] : "";
    if (strcmp(marker, "abort") == 0) {
        abort();
    }
    if (strcmp(marker, "sleep") == 0) {
        usleep(200 * 1000);
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
    const char *environment = getenv("VFORK_EXEC_TEST");
    printf("child pid=%d ppid=%d tid=%ld marker=%s env=%s\n", getpid(),
           getppid(), syscall(SYS_gettid), marker,
           environment == NULL ? "" : environment);
    return 42;
}
