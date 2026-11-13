// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Booted as litebox.init: checks that it is process 1 with no parent, and
// that it adopts and reaps orphans, as Linux init does.

#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t wait_for_new_parent(pid_t parent) {
    const struct timespec delay = {.tv_nsec = 1000000};
    for (int i = 0; i < 5000 && getppid() == parent; i++) {
        nanosleep(&delay, NULL);
    }
    return getppid();
}

int main(void) {
    pid_t self = getpid();
    pid_t parent = getppid();
    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        pid_t middle = getpid();
        pid_t grandchild = fork();
        if (grandchild == 0) {
            pid_t ids[2] = {getpid(), wait_for_new_parent(middle)};
            _exit(write(fds[1], ids, sizeof ids) != sizeof ids);
        }
        _exit(grandchild < 0);
    }
    close(fds[1]);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        perror("waitpid");
        return 1;
    }
    // The grandchild's ID, then its new parent's.
    pid_t ids[2] = {0, 0};
    if (read(fds[0], ids, sizeof ids) != sizeof ids) {
        perror("read");
        return 1;
    }
    int reaped = waitpid(-1, &status, 0) == ids[0] && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    int childless = wait(NULL) == -1 && errno == ECHILD;
    printf("pid %d\nparent %d\norphan's parent %d\nreaped the orphan %d\nno children %d\n", self,
           parent, ids[1], reaped, childless);
    return self == 1 && parent == 0 && ids[1] == 1 && reaped && childless ? 0 : 1;
}
