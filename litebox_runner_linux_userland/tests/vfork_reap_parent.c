// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
    spawn_gated("/tmp/vfork_reap_ignored");
    set_sigchld(SIG_IGN, 0);
    open_gate("/tmp/vfork_reap_ignored");
    printf("live-ignored echild=%d\n", echild(-1));

    pid_t restored = spawn_gated("/tmp/vfork_reap_restored");
    set_sigchld(SIG_DFL, 0);
    open_gate("/tmp/vfork_reap_restored");
    status = 0;
    waited = waitpid(restored, &status, 0);
    printf("live-restored child=%d waited=%d exited=%d code=%d\n", restored, waited,
           WIFEXITED(status), WEXITSTATUS(status));
    unlink("/tmp/vfork_reap_ignored");
    unlink("/tmp/vfork_reap_restored");

    // A program started while SIGCHLD is ignored keeps reaping its children.
    set_sigchld(SIG_IGN, 0);
    spawn_exec("reap-inherited", NULL);
    echild(-1);
    set_sigchld(SIG_DFL, 0);

    // Exec clears SA_NOCLDWAIT, so the new program's children are waitable.
    waitpid(spawn_exec("reap-nocldwait", NULL), NULL, 0);
    return 0;
}
