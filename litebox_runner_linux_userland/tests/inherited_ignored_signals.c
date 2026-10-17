// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: the initial program keeps the signals its launcher ignored, as across `execve`.

#include <signal.h>
#include <stdio.h>

static const char *disposition(int signal) {
    struct sigaction action;
    if (sigaction(signal, NULL, &action) != 0) {
        return "error";
    }
    return action.sa_handler == SIG_IGN ? "ignored" : "default";
}

int main(void) {
    printf("SIGHUP=%s\n", disposition(SIGHUP));
    printf("SIGINT=%s\n", disposition(SIGINT));
    printf("SIGALRM=%s\n", disposition(SIGALRM));
    printf("SIGPIPE=%s\n", disposition(SIGPIPE));
    printf("SIGTERM=%s\n", disposition(SIGTERM));
    fflush(stdout);
    // An inherited ignored disposition discards the signal instead of terminating.
    raise(SIGINT);
    printf("survived SIGINT\n");
    return 0;
}
