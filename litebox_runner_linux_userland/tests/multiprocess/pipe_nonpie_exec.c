// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: bidirectional pipe I/O with a non-PIE child binary.
//
// Parent (PIE) creates pipes, forks, child execs a static/non-PIE helper
// that echoes stdin to stdout.  This exercises the remote-exec path where
// the child needs a worker host, and pipe stdio must be bridged.
//
// The helper path is passed via the ECHO_HELPER_PATH environment variable.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define MSG "hello from parent\n"
#define EXPECTED "ECHO:hello from parent\n"

int main(void) {
    const char *helper = getenv("ECHO_HELPER_PATH");
    if (!helper) {
        fprintf(stderr, "[FAIL] ECHO_HELPER_PATH not set\n");
        return 1;
    }

    int pipe_in[2];   // parent write -> child stdin
    int pipe_out[2];  // child stdout -> parent read
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) {
        perror("pipe");
        return 2;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }

    if (pid == 0) {
        // Child: wire up pipes and exec the non-PIE helper.
        close(pipe_in[1]);
        close(pipe_out[0]);
        dup2(pipe_in[0], STDIN_FILENO);
        dup2(pipe_out[1], STDOUT_FILENO);
        close(pipe_in[0]);
        close(pipe_out[1]);

        char *nargv[] = { (char *)helper, NULL };
        char *nenvp[] = { NULL };
        execve(helper, nargv, nenvp);
        perror("execve");
        _exit(127);
    }

    // Parent: write to child's stdin, read from child's stdout.
    close(pipe_in[0]);
    close(pipe_out[1]);

    ssize_t w = write(pipe_in[1], MSG, strlen(MSG));
    if (w < 0) { perror("write"); return 2; }
    close(pipe_in[1]);  // EOF to child

    char buf[4096];
    ssize_t total = 0, n;
    while ((n = read(pipe_out[0], buf + total, sizeof(buf) - total - 1)) > 0)
        total += n;
    close(pipe_out[0]);
    buf[total] = '\0';

    int wstatus;
    waitpid(pid, &wstatus, 0);

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        fprintf(stderr, "[FAIL] child exit=%d sig=%d\n",
                WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1,
                WIFSIGNALED(wstatus) ? WTERMSIG(wstatus) : 0);
        return 1;
    }

    if (strcmp(buf, EXPECTED) != 0) {
        fprintf(stderr, "[FAIL] expected '%s', got '%s'\n", EXPECTED, buf);
        return 1;
    }

    printf("[OK] pipe_nonpie_exec: bidirectional pipe with non-PIE child works\n");
    return 0;
}
