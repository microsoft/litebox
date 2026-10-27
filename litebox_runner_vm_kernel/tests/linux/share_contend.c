// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Two processes read one open description of a share file at once, at its
// position (see bthread_hold.json and share_migrate.json, whose scripts hold
// the first read in its broker thread, asleep holding the description's lock,
// until the other's thread sleeps for it): the parent opens the host's
// greeting.txt, forks, and each reads 5 bytes; the child sends its bytes back
// over a pipe. Between them, they read "hello" and " from", in either order.

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int fd = open("/mnt/host/greeting.txt", O_RDONLY);
    int pipefd[2];
    if (fd < 0 || pipe(pipefd) != 0) {
        perror("open");
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    char mine[6] = {0};
    if (read(fd, mine, 5) != 5) {
        perror("read");
        return 2;
    }
    if (child == 0) return write(pipefd[1], mine, 5) == 5 ? 0 : 3;
    char theirs[6] = {0};
    int status;
    if (read(pipefd[0], theirs, 5) != 5 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "the child's read failed\n");
        return 1;
    }
    if (!(strcmp(mine, "hello") == 0 && strcmp(theirs, " from") == 0) &&
        !(strcmp(mine, " from") == 0 && strcmp(theirs, "hello") == 0)) {
        fprintf(stderr, "read \"%s\" and \"%s\"\n", mine, theirs);
        return 1;
    }
    printf("read: ok\n");
    return 0;
}
