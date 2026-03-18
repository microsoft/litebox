// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: cross-process pipe communication via vfork+exec.
// Parent creates pipe, vforks, child writes message, parent reads it.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define MSG "hello from child"

int main(int argc, char *argv[]) {
    const char *phase = getenv("PHASE");
    if (phase && strcmp(phase, "child") == 0) {
        if (argc < 3) return 3;
        int write_fd = atoi(argv[1]);
        int read_fd = atoi(argv[2]);

        close(read_fd);

        ssize_t n = write(write_fd, MSG, strlen(MSG));
        if (n < 0) { perror("child write"); return 2; }
        close(write_fd);
        return 0;
    }

    // Parent: create pipe, fork child, read result
    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return 2; }

    char wb[32], rb[32];
    snprintf(wb, sizeof wb, "%d", pipefd[1]);
    snprintf(rb, sizeof rb, "%d", pipefd[0]);

    pid_t child = vfork();
    if (child < 0) { perror("vfork"); return 2; }
    if (child == 0) {
        char *nargv[] = { argv[0], wb, rb, NULL };
        char *nenvp[] = { "PHASE=child", NULL };
        execve(argv[0], nargv, nenvp);
        _exit(99);
    }

    close(pipefd[1]);
    int wstatus;
    waitpid(child, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        fprintf(stderr, "[FAIL] child exit=%d\n",
                WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
        return 1;
    }

    char buf[256];
    ssize_t n = read(pipefd[0], buf, sizeof buf - 1);
    if (n < 0) { perror("parent read"); return 2; }
    buf[n] = '\0';
    close(pipefd[0]);

    if (strcmp(buf, MSG) != 0) {
        fprintf(stderr, "[FAIL] expected '%s', got '%s'\n", MSG, buf);
        return 1;
    }
    printf("[OK] pipe cross-process: '%s'\n", buf);
    return 0;
}
