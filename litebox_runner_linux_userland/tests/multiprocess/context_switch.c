// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test: fork-based context switching via synchronized pipe I/O.
// Derived from the BYTE Unix Benchmarks "context1" test.
//
// Parent and child exchange iteration counters through two pipes,
// verifying that every value round-trips correctly.  This exercises
// fork (which triggers the delayed-fork path since the child calls
// read() before exec), pipe, close, read, write, and waitpid.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define NUM_ITERATIONS 50

int main(void) {
    int p1[2], p2[2];
    ssize_t ret;

    if (pipe(p1) || pipe(p2)) {
        perror("pipe create failed");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork failed");
        return 1;
    }

    if (child > 0) {
        /* Parent: write p1, read p2. */
        close(p1[0]);
        close(p2[1]);

        for (unsigned long iter = 0; iter < NUM_ITERATIONS; iter++) {
            ret = write(p1[1], (char *)&iter, sizeof(iter));
            if (ret != (ssize_t)sizeof(iter)) {
                fprintf(stderr, "[FAIL] parent write: ret=%zd errno=%d\n",
                        ret, errno);
                return 1;
            }

            unsigned long check;
            ret = read(p2[0], (char *)&check, sizeof(check));
            if (ret != (ssize_t)sizeof(check)) {
                fprintf(stderr, "[FAIL] parent read: ret=%zd errno=%d\n",
                        ret, errno);
                return 1;
            }

            if (check != iter) {
                fprintf(stderr,
                        "[FAIL] parent sync: expected %lu, got %lu\n",
                        iter, check);
                return 1;
            }
        }

        close(p1[1]);
        close(p2[0]);

        int wstatus;
        waitpid(child, &wstatus, 0);
        if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
            fprintf(stderr, "[FAIL] child exit status=%d\n",
                    WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
            return 1;
        }

        printf("[OK] context_switch: %d iterations\n", NUM_ITERATIONS);
        return 0;
    } else {
        /* Child: read p1, write p2. */
        close(p1[1]);
        close(p2[0]);

        for (unsigned long iter = 0; iter < NUM_ITERATIONS; iter++) {
            unsigned long check;
            ret = read(p1[0], (char *)&check, sizeof(check));
            if (ret != (ssize_t)sizeof(check)) {
                if (ret == 0) _exit(0); /* parent closed pipe */
                fprintf(stderr, "[FAIL] child read: ret=%zd errno=%d\n",
                        ret, errno);
                _exit(1);
            }

            if (check != iter) {
                fprintf(stderr,
                        "[FAIL] child sync: expected %lu, got %lu\n",
                        iter, check);
                _exit(2);
            }

            ret = write(p2[1], (char *)&iter, sizeof(iter));
            if (ret != (ssize_t)sizeof(iter)) {
                fprintf(stderr, "[FAIL] child write: ret=%zd errno=%d\n",
                        ret, errno);
                _exit(1);
            }
        }

        close(p1[0]);
        close(p2[1]);
        _exit(0);
    }
}
