// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: pipe2(O_CLOEXEC) fds should be closed in child after exec.

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    const char *phase = getenv("PHASE");
    if (phase && strcmp(phase, "child") == 0) {
        if (argc < 2) return 3;
        int cloexec_fd = atoi(argv[1]);
        // This fd should have been closed by close_on_exec
        int rc = fcntl(cloexec_fd, F_GETFD);
        if (rc >= 0) {
            fprintf(stderr, "[FAIL] cloexec fd %d survived exec (flags=%d)\n",
                    cloexec_fd, rc);
            return 1;
        }
        if (errno != EBADF) {
            fprintf(stderr, "[FAIL] expected EBADF, got errno=%d\n", errno);
            return 1;
        }
        printf("[OK] cloexec fd properly closed after exec\n");
        return 0;
    }

    // Parent: create pipe with O_CLOEXEC
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) { perror("pipe2"); return 2; }

    char fb[32];
    snprintf(fb, sizeof fb, "%d", pipefd[1]);

    pid_t child = vfork();
    if (child < 0) { perror("vfork"); return 2; }
    if (child == 0) {
        char *nargv[] = { argv[0], fb, NULL };
        char *nenvp[] = { "PHASE=child", NULL };
        execve(argv[0], nargv, nenvp);
        _exit(99);
    }

    int wstatus;
    waitpid(child, &wstatus, 0);
    close(pipefd[0]);
    close(pipefd[1]);

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        fprintf(stderr, "[FAIL] child exit=%d\n",
                WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
        return 1;
    }
    return 0;
}
