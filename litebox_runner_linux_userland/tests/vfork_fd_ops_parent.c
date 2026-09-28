// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_PATH "/tmp/vfork_fd_ops_log"
#define OPENED_FD 10

extern char **environ;

static int is_open(int fd) { return fcntl(fd, F_GETFD) != -1; }

static int is_cloexec(int fd) { return fcntl(fd, F_GETFD) == FD_CLOEXEC; }

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }

    int log = open(LOG_PATH, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    // A close-on-exec descriptor far above the others, which the children also get.
    int high[300];
    for (int i = 0; i < 300; i++) {
        high[i] = fcntl(log, F_DUPFD_CLOEXEC, 0);
    }
    for (int i = 0; i < 299; i++) {
        close(high[i]);
    }
    // The spawned child closes the pipe in its own table, so its fresh runner does not inherit it.
    int p[2];
    if (log < 0 || high[299] < 0 || pipe2(p, O_NONBLOCK) != 0) {
        perror("setup");
        return 3;
    }

    // The child reports its descriptors through its stdout, which is `log`.
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, p[0]);
    posix_spawn_file_actions_addclose(&actions, p[1]);
    posix_spawn_file_actions_adddup2(&actions, log, 1);
    posix_spawn_file_actions_adddup2(&actions, log, log);
    posix_spawn_file_actions_addopen(&actions, OPENED_FD, LOG_PATH, O_RDONLY, 0);
    char *child_argv[] = {argv[1], "open-fds", NULL};
    fflush(stdout);
    pid_t child;
    int ret = posix_spawn(&child, argv[1], &actions, NULL, child_argv, environ);
    int status = 0;
    pid_t waited = ret == 0 ? waitpid(child, &status, 0) : -1;
    int opened_closed = !is_open(OPENED_FD) && errno == EBADF;
    off_t offset = lseek(log, 0, SEEK_CUR);
    char contents[512];
    ssize_t length = pread(log, contents, sizeof contents, 0);
    printf("spawn ret=%d exited=%d code=%d log_cloexec=%d pipe_open=%d opened_closed=%d "
           "offset=%lld length=%zd\n",
           ret, waited == child && WIFEXITED(status), WEXITSTATUS(status), is_cloexec(log),
           is_open(p[0]) && is_open(p[1]), opened_closed, (long long)offset, length);
    if (length > 0) {
        fwrite(contents, 1, length, stdout);
    }

    // The child changes its own descriptors and exits without `execve`.
    fflush(stdout);
    child = vfork();
    if (child == 0) {
        if (!is_cloexec(log) || fcntl(log, F_SETFD, 0) != 0 || dup2(p[1], 1) != 1 ||
            close(p[1]) != 0 || write(1, "x", 1) != 1) {
            _exit(1);
        }
        _exit(0);
    }
    waited = child < 0 ? -1 : waitpid(child, &status, 0);
    int pipe_open = is_open(p[0]) && is_open(p[1]);
    close(p[1]);
    // The pipe reaches end-of-file only once the child's copies of its write end are closed too.
    char byte = 0;
    ssize_t first = read(p[0], &byte, 1);
    ssize_t second = read(p[0], &byte, 1);
    printf("vfork exited=%d code=%d log_cloexec=%d pipe_open=%d first=%zd byte=%c second=%zd\n",
           waited == child && WIFEXITED(status), WEXITSTATUS(status), is_cloexec(log), pipe_open,
           first, byte, second);
    return 0;
}
