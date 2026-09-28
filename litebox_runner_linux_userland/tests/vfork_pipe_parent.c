// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

// Several times the capacity of a pipe, so writes wait for the child to read.
#define STREAM_SIZE (256 * 1024)

extern char **environ;

static char stream[STREAM_SIZE];

// Spawns the child with `marker` and `fd` as its descriptor `target`.
static pid_t spawn_with(const char *path, char *marker, int fd, int target) {
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fd, target);
    char *child_argv[] = {(char *)path, marker, NULL};
    fflush(stdout);
    pid_t child;
    int ret = posix_spawn(&child, path, &actions, NULL, child_argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    return ret == 0 ? child : -1;
}

// Returns the exit code of `child`, or -1 if it did not exit normally.
static int exit_code(pid_t child) {
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    for (size_t i = 0; i < STREAM_SIZE; i++) {
        stream[i] = 'a' + i % 26;
    }

    // The child writes its stdout into a pipe, which reaches end-of-file once the child exits.
    int out[2];
    if (pipe2(out, O_CLOEXEC) != 0) {
        perror("pipe2");
        return 3;
    }
    pid_t child = spawn_with(path, "stdout-mode", out[1], 1);
    close(out[1]);
    char text[256];
    size_t length = 0;
    ssize_t n;
    while (length < sizeof text - 1 && (n = read(out[0], text + length, sizeof text - 1 - length)) > 0) {
        length += n;
    }
    text[length] = '\0';
    close(out[0]);
    printf("stdout-pipe code=%d eof=%d\n", exit_code(child), n == 0);
    printf("%s", text);

    // The child reads its stdin, whose status flags it inherits, from a pipe the parent fills.
    int in[2];
    if (pipe2(in, O_CLOEXEC) != 0 || fcntl(in[0], F_SETFL, O_NONBLOCK) != 0) {
        perror("pipe2");
        return 3;
    }
    child = spawn_with(path, "cat", in[0], 0);
    close(in[0]);
    // Let the child block waiting for input, which only the parent's writes can end.
    usleep(100 * 1000);
    ssize_t written = write(in[1], stream, STREAM_SIZE);
    close(in[1]);
    printf("stdin-pipe code=%d written=%zd\n", exit_code(child), written);

    // A reader that exits early ends the parent's blocked write.
    signal(SIGPIPE, SIG_IGN);
    int early[2];
    if (pipe2(early, O_CLOEXEC) != 0) {
        perror("pipe2");
        return 3;
    }
    child = spawn_with(path, "read-byte", early[0], 0);
    close(early[0]);
    ssize_t first = write(early[1], stream, STREAM_SIZE);
    ssize_t second = write(early[1], stream, 1);
    int second_errno = errno;
    close(early[1]);
    printf("early-reader code=%d partial=%d second=%zd epipe=%d\n", exit_code(child),
           first > 0 && first < STREAM_SIZE, second, second_errno == EPIPE);
    return 0;
}
