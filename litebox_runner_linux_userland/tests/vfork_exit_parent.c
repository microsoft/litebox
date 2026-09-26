// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int wait_for(pid_t child_pid, const char *name) {
    int status = 0;
    pid_t waited = waitpid(child_pid, &status, 0);
    printf("%s child=%d waited=%d exited=%d code=%d\n", name, child_pid, waited,
           WIFEXITED(status), WEXITSTATUS(status));
    return waited == child_pid ? 0 : 1;
}

int main(void) {
    pid_t parent_before = getpid();
    printf("vfork-started\n");
    fflush(stdout);

    pid_t exit_group_child = vfork();
    if (exit_group_child == 0) {
        _exit(37);
    }
    if (exit_group_child < 0) {
        perror("vfork");
        return 2;
    }
    int failures = wait_for(exit_group_child, "exit_group");

    pid_t exit_child = vfork();
    if (exit_child == 0) {
        // Only the low byte of the status is reported.
        syscall(SYS_exit, 256 + 38);
        _exit(111);
    }
    if (exit_child < 0) {
        perror("vfork");
        return 3;
    }
    failures += wait_for(exit_child, "exit");

    pid_t again = waitpid(-1, NULL, WNOHANG);
    int again_errno = errno;
    printf("parent before=%d after=%d echild=%d\n", parent_before, getpid(),
           again == -1 && again_errno == ECHILD);
    return failures;
}
