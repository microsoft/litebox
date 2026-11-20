// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t parent_before;

// Reaps `child_pid`, reporting it as `name`, and returns whether it failed to exit with `code`.
static int wait_for(pid_t child_pid, const char *name, int code) {
    int status = 0;
    pid_t waited = waitpid(child_pid, &status, 0);
    printf("%s child=%d waited=%d exited=%d code=%d\n", name, child_pid, waited,
           WIFEXITED(status), WEXITSTATUS(status));
    return waited != child_pid || child_pid == parent_before || !WIFEXITED(status) ||
           WEXITSTATUS(status) != code;
}

// A vfork child that exits, by any route, resumes its parent, which can wait for it.
int main(void) {
    parent_before = getpid();
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
    int failures = wait_for(exit_group_child, "exit_group", 37);

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
    failures += wait_for(exit_child, "exit", 38);

    // An allowed syscall with invalid arguments fails in the child; its errno is the exit code.
    pid_t bad_args_child = vfork();
    if (bad_args_child == 0) {
        uint64_t set = 0;
        long rc = syscall(SYS_rt_sigprocmask, 99 /* invalid `how` */, &set, NULL, sizeof(set));
        _exit(rc == -1 ? errno : 0);
    }
    if (bad_args_child < 0) {
        perror("vfork");
        return 5;
    }
    failures += wait_for(bad_args_child, "bad_args", EINVAL);

    // Cancel an alarm before vfork, as busybox httpd does before running a CGI program.
    alarm(60);
    if (alarm(0) == 0) {
        return 6;
    }
    pid_t disarmed_child = vfork();
    if (disarmed_child == 0) {
        _exit(39);
    }
    if (disarmed_child < 0) {
        perror("vfork after alarm(0)");
        return 4;
    }
    failures += wait_for(disarmed_child, "disarmed", 39);

    pid_t again = waitpid(-1, NULL, WNOHANG);
    int again_errno = errno;
    int echild = again == -1 && again_errno == ECHILD;
    printf("parent before=%d after=%d echild=%d\n", parent_before, getpid(), echild);
    return failures + (getpid() != parent_before) + !echild;
}
