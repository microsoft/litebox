// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
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

// The exec'd child sleeps before exiting with code 42, so it is still live when the parent
// resumes.
static pid_t spawn_sleeper(void) {
    pid_t child = vfork();
    if (child == 0) {
        execl(child_path, child_path, "sleep", (char *)NULL);
        _exit(111);
    }
    if (child < 0) {
        perror("vfork");
        _exit(5);
    }
    return child;
}

static int echild(pid_t pid) {
    return waitpid(pid, NULL, 0) == -1 && errno == ECHILD;
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

    // Blocking waits return once the children are reaped.
    pid_t ignored = spawn_exit(22);
    printf("ignored echild=%d\n", echild(ignored));

    set_sigchld(SIG_DFL, SA_NOCLDWAIT);
    spawn_exit(23);
    printf("nocldwait echild=%d\n", echild(-1));

    // A live child follows a later disposition change.
    set_sigchld(SIG_DFL, 0);
    spawn_sleeper();
    set_sigchld(SIG_IGN, 0);
    printf("live-ignored echild=%d\n", echild(-1));

    pid_t restored = spawn_sleeper();
    set_sigchld(SIG_DFL, 0);
    status = 0;
    waited = waitpid(restored, &status, 0);
    printf("live-restored child=%d waited=%d exited=%d code=%d\n", restored, waited,
           WIFEXITED(status), WEXITSTATUS(status));
    return 0;
}
