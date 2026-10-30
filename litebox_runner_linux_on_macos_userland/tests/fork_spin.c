// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Forks, then spins without system calls in both processes, so only the runner can end them. The
// child spins on its initial thread. The parent's initial thread starts a spinning sibling and
// exits alone; the sibling reports once that exit has cleared `initial_thread_tid`.

#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile int initial_thread_tid;

static void *spin_after_initial_thread_exits(void *unused) {
    (void)unused;
    while (initial_thread_tid != 0) {
    }
    printf("spinning parent\n");
    fflush(stdout);
    for (;;) {
    }
}

int main(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        printf("spinning child\n");
        fflush(stdout);
        for (;;) {
        }
    }
    initial_thread_tid = (int)syscall(SYS_gettid);
    // The kernel zeroes the word when this thread exits.
    syscall(SYS_set_tid_address, &initial_thread_tid);
    pthread_t sibling;
    if (pthread_create(&sibling, NULL, spin_after_initial_thread_exits, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    // Exits only this thread, unlike `exit` or returning from `main`.
    syscall(SYS_exit, 0);
    return 1;
}
