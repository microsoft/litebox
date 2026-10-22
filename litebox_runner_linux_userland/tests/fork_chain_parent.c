// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Runs a fork chain, in which each generation forks the next and passes the last one's exit code
// back up. Usage: fork_chain_parent <fork|exec> <depth>. In "exec" mode each child execs this
// program to continue the chain.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

// Exit code of the last generation, which reaching the top shows that every generation ran.
#define LEAF_CODE 42

static pid_t fork_flushed(void) {
    fflush(stdout);
    return fork();
}

// Waits for `child`, returning its exit code, or 1 if it did not exit normally.
static int wait_code(pid_t child) {
    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

// Forks `depth` generations below the caller, each the child of the one before, and returns the
// exit code the chain passes back up.
static int fork_chain(int depth) {
    for (int generation = 0; generation < depth; generation++) {
        pid_t child = fork_flushed();
        if (child < 0) {
            perror("fork");
            return 1;
        }
        if (child > 0) {
            return wait_code(child);
        }
    }
    return LEAF_CODE;
}

// Forks one generation that execs this program to continue a chain of `depth` generations, and
// returns the exit code the chain passes back up.
static int exec_chain(char *self, int depth) {
    if (depth == 0) {
        return LEAF_CODE;
    }
    pid_t child = fork_flushed();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        char remaining[16];
        snprintf(remaining, sizeof remaining, "%d", depth - 1);
        char *argv[] = {self, "exec", remaining, "nested", NULL};
        execv(self, argv);
        perror("execv");
        _exit(1);
    }
    return wait_code(child);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <fork|exec> <depth>\n", argv[0]);
        return 2;
    }
    int depth = atoi(argv[2]);
    pid_t top = getpid();
    int code;
    if (strcmp(argv[1], "fork") == 0) {
        code = fork_chain(depth);
    } else if (strcmp(argv[1], "exec") == 0) {
        code = exec_chain(argv[0], depth);
    } else {
        fprintf(stderr, "unknown mode %s\n", argv[1]);
        return 2;
    }
    // Only the first process of the chain reports; in "exec" mode, every later one is nested.
    if (getpid() == top && argc == 3) {
        printf("%s-chain depth=%d code=%d\n", argv[1], depth, code);
        return code == LEAF_CODE ? 0 : 1;
    }
    return code;
}
