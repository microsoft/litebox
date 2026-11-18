// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that every run (see init.json) is a child of process 1, the guest
// service, leads its own session and process group, and that an orphan of
// its descendants becomes process 1's child. It prints each check, and exits
// 0 only if all hold.
//
// The orphan comes from a chain of spawned processes: this one starts a
// child ("middle <fd>"), which starts the orphan ("orphan <fd> <parent>")
// and exits at once; the orphan writes its new parent's ID to <fd>, a pipe
// this process reads.

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static pid_t wait_for_new_parent(pid_t parent) {
    const struct timespec delay = {.tv_nsec = 1000000};
    for (int i = 0; i < 5000 && getppid() == parent; i++) {
        nanosleep(&delay, NULL);
    }
    return getppid();
}

static int spawn(char *const argv[]) {
    pid_t pid;
    int err = posix_spawn(&pid, argv[0], NULL, NULL, argv, environ);
    if (err != 0) {
        printf("posix_spawn: %s\n", strerror(err));
        return -1;
    }
    return pid;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "middle") == 0) {
        char parent[16];
        snprintf(parent, sizeof parent, "%d", getpid());
        char *orphan[] = {"/init", "orphan", argv[2], parent, NULL};
        return spawn(orphan) < 0;
    }
    if (argc == 4 && strcmp(argv[1], "orphan") == 0) {
        pid_t adopter = wait_for_new_parent(atoi(argv[3]));
        return write(atoi(argv[2]), &adopter, sizeof adopter) != sizeof adopter;
    }

    pid_t self = getpid();
    pid_t parent = getppid();
    int leader = getsid(0) == self && getpgrp() == self;

    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 1;
    }
    char fd[16];
    snprintf(fd, sizeof fd, "%d", fds[1]);
    char *middle[] = {"/init", "middle", fd, NULL};
    pid_t child = spawn(middle);
    close(fds[1]);
    if (child < 0 || waitpid(child, NULL, 0) != child) {
        perror("waitpid");
        return 1;
    }
    // The orphan's new parent.
    pid_t adopter = 0;
    if (read(fds[0], &adopter, sizeof adopter) != sizeof adopter) {
        perror("read");
        return 1;
    }
    int adopted = adopter == 1;
    int childless = wait(NULL) == -1 && errno == ECHILD;
    printf("parent %d\nleader %d\nprocess 1 adopted the orphan %d\nno children %d\n", parent,
           leader, adopted, childless);
    return parent == 1 && leader && adopted && childless ? 0 : 1;
}
