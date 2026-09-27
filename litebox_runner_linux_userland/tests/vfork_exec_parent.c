// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path [marker]\n", argv[0]);
        return 2;
    }

    pid_t parent_before = getpid();
    char *child_argv[] = {argv[1], argc == 3 ? argv[2] : "from-vfork", NULL};
    char *child_envp[] = {"VFORK_EXEC_TEST=1", NULL};
    printf("vfork-started\n");
    fflush(stdout);
    pid_t child_pid = vfork();
    if (child_pid == 0) {
        // A failed exec returns to the child, which may try again.
        if (execve("/missing-vfork-executable", child_argv, child_envp) != -1 ||
            errno != ENOENT) {
            _exit(112);
        }
        // Relative to the root working directory.
        execve(argv[1] + 1, child_argv, child_envp);
        _exit(111);
    }
    if (child_pid < 0) {
        perror("vfork");
        printf("vfork-error\n");
        return 3;
    }

    pid_t parent_after = getpid();
    int status = 0;
    pid_t waited = waitpid(child_pid, &status, 0);
    pid_t again = waitpid(-1, NULL, WNOHANG);
    int again_errno = errno;
    printf("parent before=%d after=%d child=%d waited=%d exited=%d code=%d "
           "signaled=%d signal=%d again=%d echild=%d\n",
           parent_before, parent_after, child_pid, waited, WIFEXITED(status),
           WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status), again,
           again == -1 && again_errno == ECHILD);
    return parent_before == parent_after ? 0 : 4;
}
