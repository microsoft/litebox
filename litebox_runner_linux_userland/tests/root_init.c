// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The guest's first process, which its child tries to kill. With the argument `init`, it expects to
// run as the guest's init (`--root-process-as-init`).

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static volatile sig_atomic_t usr2_handled;

static void on_usr2(int signal) {
    (void)signal;
    usr2_handled = 1;
}

// Returns whether `pid` exited with `code`.
static int exited_with(pid_t pid, int code) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

// Returns whether `signal` is pending for this process.
static int is_pending(int signal) {
    sigset_t pending;
    return sigpending(&pending) == 0 && sigismember(&pending, signal) == 1;
}

int main(int argc, char **argv) {
    int init = argc > 1 && strcmp(argv[1], "init") == 0;
    printf("root-init started\n");
    CHECK(getpid() == 1 && getppid() == 0);
    signal(SIGUSR2, on_usr2);
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigprocmask(SIG_BLOCK, &usr1, NULL);

    fflush(stdout);
    pid_t sender = fork();
    if (sender == 0) {
        int sent = kill(1, SIGTERM) == 0 && kill(1, SIGKILL) == 0 && kill(1, SIGUSR1) == 0 &&
                   kill(1, SIGUSR2) == 0;
        _exit(sent ? 0 : 1);
    }
    // Reaping the sender takes the signals it sent first.
    CHECK(exited_with(sender, 0));
    if (!init) {
        printf("root-init survived as an ordinary program\n");
        return 1;
    }
    CHECK(usr2_handled);
    CHECK(is_pending(SIGUSR1));
    CHECK(sigprocmask(SIG_UNBLOCK, &usr1, NULL) == 0 && !is_pending(SIGUSR1));
    CHECK(raise(SIGTERM) == 0 && raise(SIGINT) == 0);

    // Init's exit must kill this child.
    fflush(stdout);
    pid_t survivor = fork();
    if (survivor == 0) {
        sleep(10);
        printf("root-init outlived by %d\n", (int)getpid());
        _exit(0);
    }
    CHECK(survivor > 0);
    printf("root-init failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
