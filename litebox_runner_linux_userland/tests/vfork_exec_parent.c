// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
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
    printf("parent before=%d after=%d child=%d\n", parent_before, parent_after,
           child_pid);
    return parent_before == parent_after ? 0 : 4;
}
