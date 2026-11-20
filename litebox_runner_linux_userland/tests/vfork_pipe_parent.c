// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A spawned child shares pipes with its parent: the parent reads the child's stdout until the
// child's exit closes it, each waits for the other to drain or fill a pipe, the child's stdin shares
// its status flags with the parent's end, and the child's exit wakes a parent blocked writing a
// full pipe.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

// Several times the capacity of a pipe, so writes wait for the child to read.
#define STREAM_SIZE (256 * 1024)

extern char **environ;

static char stream[STREAM_SIZE];

// Spawns the child with `marker`, `argument` if not `NULL`, and `fd` as its descriptor `target`.
static pid_t spawn_with(const char *path, char *marker, char *argument, int fd, int target) {
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fd, target);
    char *child_argv[] = {(char *)path, marker, argument, NULL};
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
    pid_t child = spawn_with(path, "stdout-mode", NULL, out[1], 1);
    close(out[1]);
    char text[256];
    size_t length = 0;
    ssize_t n;
    while (length < sizeof text - 1 && (n = read(out[0], text + length, sizeof text - 1 - length)) > 0) {
        length += n;
    }
    text[length] = '\0';
    close(out[0]);
    int code = exit_code(child);
    printf("stdout-pipe code=%d eof=%d\n", code, n == 0);
    printf("%s", text);
    // The child's stdout is the pipe's write end, and it has only the standard streams.
    int failures = code != 42 || n != 0 ||
                   strcmp(text, "child-stdout wronly=1\nchild-open-fds 0 1 2\n") != 0;

    // The child reads its stdin, whose status flags it shares, from a pipe the parent fills.
    int in[2];
    if (pipe2(in, O_CLOEXEC) != 0 || fcntl(in[0], F_SETFL, O_NONBLOCK) != 0) {
        perror("pipe2");
        return 3;
    }
    char stream_size[16];
    snprintf(stream_size, sizeof stream_size, "%d", STREAM_SIZE);
    child = spawn_with(path, "cat", stream_size, in[0], 0);
    // Let the child block waiting for input, which only the parent's writes can end.
    usleep(100 * 1000);
    ssize_t written = write(in[1], stream, STREAM_SIZE);
    close(in[1]);
    code = exit_code(child);
    // The child clears O_NONBLOCK on its stdin before exiting.
    int flags = fcntl(in[0], F_GETFL);
    close(in[0]);
    int shared_setfl = flags >= 0 && (flags & O_NONBLOCK) == 0;
    printf("stdin-pipe code=%d written=%zd shared_setfl=%d\n", code, written, shared_setfl);
    // The child read the whole stream from a nonblocking, read-only stdin.
    failures += code != 42 || written != STREAM_SIZE || !shared_setfl;

    // A reader that exits early ends the parent's blocked write.
    signal(SIGPIPE, SIG_IGN);
    int early[2];
    if (pipe2(early, O_CLOEXEC) != 0) {
        perror("pipe2");
        return 3;
    }
    child = spawn_with(path, "read-byte", "a", early[0], 0);
    close(early[0]);
    ssize_t first = write(early[1], stream, STREAM_SIZE);
    ssize_t second = write(early[1], stream, 1);
    int second_errno = errno;
    close(early[1]);
    code = exit_code(child);
    int partial = first > 0 && first < STREAM_SIZE;
    printf("early-reader code=%d partial=%d second=%zd epipe=%d\n", code, partial, second,
           second_errno == EPIPE);
    // The child read the stream's first byte.
    failures += code != 42 || !partial || second != -1 || second_errno != EPIPE;
    return failures != 0;
}
