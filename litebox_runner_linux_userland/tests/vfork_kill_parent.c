// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *child_path;

static volatile sig_atomic_t usr2_count;
static volatile pid_t usr2_pid;
static volatile int usr2_code;
static volatile int usr2_uid_matches;

static void on_usr2(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    usr2_count++;
    usr2_pid = info->si_pid;
    usr2_code = info->si_code;
    usr2_uid_matches = info->si_uid == getuid();
}

static pid_t spawn(const char *marker) {
    pid_t child = vfork();
    if (child == 0) {
        execl(child_path, child_path, marker, (char *)NULL);
        _exit(111);
    }
    if (child < 0) {
        perror("vfork");
        _exit(4);
    }
    return child;
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }
    child_path = argv[1];

    struct sigaction action = {.sa_sigaction = on_usr2, .sa_flags = SA_SIGINFO | SA_RESTART};
    if (sigaction(SIGUSR2, &action, NULL) != 0) {
        perror("sigaction");
        return 3;
    }

    // The child signals the parent once it handles SIGUSR1, and the parent signals it back.
    pid_t child = spawn("kill-handshake");
    for (int i = 0; i < 5000 && usr2_count == 0; i++) {
        usleep(1000);
    }
    int alive = kill(child, 0) == 0;
    int sent = kill(child, SIGUSR1) == 0;
    int status = 0;
    pid_t waited = waitpid(child, &status, 0);
    printf("handshake child=%d waited=%d count=%d pid=%d code=%d uid=%d alive=%d sent=%d "
           "exit=%d\n",
           child, waited, usr2_count, usr2_pid, usr2_code, usr2_uid_matches, alive, sent,
           WEXITSTATUS(status));

    // A signal sent as soon as the child starts terminates it, even before it can take signals.
    child = spawn("kill-wait");
    sent = kill(child, SIGKILL) == 0;
    status = 0;
    waited = waitpid(child, &status, 0);
    printf("killed child=%d waited=%d sent=%d signaled=%d signal=%d\n", child, waited, sent,
           WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0);

    errno = 0;
    int missing = kill(INT_MAX, SIGTERM) == -1 && errno == ESRCH;
    errno = 0;
    int missing_check = kill(INT_MAX, 0) == -1 && errno == ESRCH;
    printf("missing esrch=%d check_esrch=%d self_check=%d\n", missing, missing_check,
           kill(getpid(), 0) == 0);
    return 0;
}
