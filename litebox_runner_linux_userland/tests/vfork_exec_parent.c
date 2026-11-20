// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A vfork child's `execve` starts the child's program, as the process the parent got for the child,
// and resumes the parent, which then waits for the child: one that exits, one that dies of a signal,
// and one whose `execve` fails, returning the error to the child.

#include "helpers.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define MISSING "/missing-vfork-executable"

static pid_t parent_before;

// Vforks a child that runs `path` with `marker`, waits for it, and returns its wait status, or -1
// if the parent didn't resume as itself or didn't reap exactly that child, or if `reports`, but the
// child didn't report itself as that child.
static int run(const char *path, const char *marker, int reports) {
    char *child_argv[] = {(char *)path, (char *)marker, NULL};
    char parent[32];
    snprintf(parent, sizeof parent, "VFORK_EXEC_PARENT=%d", parent_before);
    struct pid_report report;
    open_pid_report(&report);
    char *child_envp[] = {"VFORK_EXEC_TEST=vfork", parent, report.variable, NULL};
    fflush(stdout);
    pid_t child_pid = vfork();
    if (child_pid == 0) {
        // A failed exec returns to the child, which may try again.
        if (execve(MISSING, child_argv, child_envp) != -1 || errno != ENOENT) {
            _exit(112);
        }
        // Relative to the root working directory.
        execve(path + 1, child_argv, child_envp);
        _exit(111);
    }
    if (child_pid < 0) {
        perror("vfork");
        return -1;
    }

    pid_t parent_after = getpid();
    int status = 0;
    pid_t waited = waitpid(child_pid, &status, 0);
    pid_t again = waitpid(-1, NULL, WNOHANG);
    int echild = again == -1 && errno == ECHILD;
    int reported = pid_reported(&report, child_pid);
    printf("parent marker=%s before=%d after=%d child=%d waited=%d exited=%d code=%d "
           "signaled=%d signal=%d again=%d echild=%d reported=%d\n",
           marker, parent_before, parent_after, child_pid, waited, WIFEXITED(status),
           WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status), again, echild, reported);
    return parent_after == parent_before && child_pid != parent_before && waited == child_pid &&
                   echild && (reported || !reports)
               ? status
               : -1;
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }
    parent_before = getpid();
    if (chdir("/") != 0) {
        perror("chdir");
        return 2;
    }
    printf("vfork-started\n");

    int failures = 0;
    // The child checks that it is this process's child, with the marker and environment passed.
    int status = run(argv[1], "from-vfork", 1);
    failures += status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
    status = run(argv[1], "abort", 0);
    failures += status == -1 || !WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT;
    status = run(MISSING, "from-vfork", 0);
    failures += status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 111;
    printf("vfork-exec failures=%d\n", failures);
    return failures != 0;
}
