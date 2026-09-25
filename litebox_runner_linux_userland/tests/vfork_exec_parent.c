// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }

    pid_t parent_before = getpid();
    char *child_argv[] = {argv[1], "from-vfork", NULL};
    char *child_envp[] = {"VFORK_EXEC_TEST=1", NULL};
    printf("vfork-started\n");
    fflush(stdout);
    pid_t child_pid = vfork();
    if (child_pid == 0) {
        execve(argv[1], child_argv, child_envp);
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
           "again=%d echild=%d\n",
           parent_before, parent_after, child_pid, waited, WIFEXITED(status),
           WEXITSTATUS(status), again, again == -1 && again_errno == ECHILD);
    return parent_before == parent_after ? 0 : 4;
}
