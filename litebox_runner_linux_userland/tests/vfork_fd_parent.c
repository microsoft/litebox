// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A vfork child's `execve` keeps the descriptors not marked close-on-exec, which share their open
// file descriptions, offsets and status flags, with the parent's.

#define _GNU_SOURCE
#include "helpers.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define STDIN_ALIAS 40

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }

    char *log_path = test_path("vfork_fd_log");
    int log = open(log_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    int hidden = open(log_path, O_RDONLY | O_CLOEXEC);
    fflush(stdout);
    int saved_stdout = fcntl(1, F_DUPFD_CLOEXEC, 0);
    if (log < 0 || hidden < 0 || saved_stdout < 0 || dup2(log, 1) != 1 ||
        dup2(0, STDIN_ALIAS) != STDIN_ALIAS) {
        perror("setup");
        return 3;
    }

    // The child writes the log through its stdout and `log`, which share an offset, checks that
    // `hidden` stays behind, and makes the stdin alias non-blocking, which the parent's stdin
    // shares.
    char log_arg[16], stdin_alias_arg[16], hidden_arg[16];
    snprintf(log_arg, sizeof log_arg, "%d", log);
    snprintf(stdin_alias_arg, sizeof stdin_alias_arg, "%d", STDIN_ALIAS);
    snprintf(hidden_arg, sizeof hidden_arg, "%d", hidden);
    char *child_argv[] = {argv[1], "fds", log_arg, stdin_alias_arg, hidden_arg, NULL};
    pid_t child = vfork();
    if (child == 0) {
        execv(argv[1], child_argv);
        _exit(111);
    }
    int status = 0;
    pid_t waited = child < 0 ? -1 : waitpid(child, &status, 0);
    off_t offset = lseek(1, 0, SEEK_CUR);
    int stdin_flags = fcntl(0, F_GETFL);
    int stdin_nonblock = stdin_flags < 0 ? -1 : (stdin_flags & O_NONBLOCK) != 0;
    dup2(saved_stdout, 1);
    if (child < 0) {
        perror("vfork");
        return 3;
    }

    char contents[512];
    ssize_t length = pread(hidden, contents, sizeof contents, 0);
    printf("parent child=%d waited=%d exited=%d code=%d offset=%lld length=%zd "
           "stdin_nonblock=%d\n",
           child, waited, WIFEXITED(status), WEXITSTATUS(status), (long long)offset, length,
           stdin_nonblock);
    if (length > 0) {
        fwrite(contents, 1, length, stdout);
    }
    // The child wrote, in order, through both descriptors that share the log's offset.
    static const char expected[] = "child-fds via-stdout\n"
                                   "child-fds via-log\n"
                                   "child-fds stdin_setfl=1 hidden_closed=1\n";
    int logged = length == (ssize_t)(sizeof expected - 1) &&
                 memcmp(contents, expected, sizeof expected - 1) == 0;
    // The child's `F_SETFL` changed the open file description the parent's stdin shares.
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 42 && logged &&
                   offset == length && stdin_nonblock == 1
               ? 0
               : 1;
}
