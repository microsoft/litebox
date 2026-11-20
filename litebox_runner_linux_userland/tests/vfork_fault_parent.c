// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

// A vfork child that faults dies of the fault's signal, and its parent resumes as itself and
// reaps it.
int main(void) {
    pid_t parent_before = getpid();
    printf("vfork-started\n");
    fflush(stdout);

    pid_t child_pid = vfork();
    if (child_pid == 0) {
        __builtin_trap();
        _exit(111);
    }
    if (child_pid < 0) {
        perror("vfork");
        printf("vfork-error\n");
        return 2;
    }

    int status = 0;
    pid_t waited = waitpid(child_pid, &status, 0);
    pid_t again = waitpid(-1, NULL, WNOHANG);
    int again_errno = errno;
    int echild = again == -1 && again_errno == ECHILD;
    printf("parent before=%d after=%d child=%d waited=%d signaled=%d "
           "signal=%d echild=%d\n",
           parent_before, getpid(), child_pid, waited, WIFSIGNALED(status),
           WTERMSIG(status), echild);
    if (waited != child_pid) {
        return 3;
    }
    return getpid() == parent_before && child_pid != parent_before && WIFSIGNALED(status) &&
                   WTERMSIG(status) == TRAP_SIGNAL && echild
               ? 0
               : 4;
}
