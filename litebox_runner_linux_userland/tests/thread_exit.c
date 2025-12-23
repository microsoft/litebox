// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <string.h>

void* yield_thread(void* arg) {
    for (;;) {
        sched_yield();
    }
}

void* spin_thread(void* arg) {
    for (;;) {
        __asm__ __volatile__("pause");
    }
}

void* futex_thread(void* arg) {
    volatile int futex_var = 0;
    for (;;) {
        int r = syscall(SYS_futex, &futex_var, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
        if (r >= 0) {
            fprintf(stderr, "futex wait returned unexpectedly\n");
            abort();
        }
        if (errno != EINTR) {
            perror("futex wait failed");
            abort();
        }
    }
}

void* exit_thread(void* arg) {
    // Wait a bit before exiting.
    usleep(500000);
    exit(0);
}

int main() {
    // Create a bunch of threads doing different things to make sure they get
    // terminated when the process exits.
    typedef void* (*thread_func_t)(void*);
    thread_func_t funcs[] = {yield_thread, spin_thread, futex_thread};
    for (int i = 0; i < 20; i++) {
        pthread_t thread;
        int rc = pthread_create(&thread, NULL, funcs[i % sizeof(funcs) / sizeof(funcs[0])], NULL);
        if (rc) {
            fprintf(stderr, "pthread_create: %s\n", strerror(rc));
            abort();
        }
        pthread_detach(thread);
    }

    // Create a thread to exit the process.
    {
        pthread_t thread;
        int rc = pthread_create(&thread, NULL, exit_thread, NULL);
        if (rc) {
            fprintf(stderr, "pthread_create: %s\n", strerror(rc));
            abort();
        }
        pthread_detach(thread);
    }

    // Exit this thread so that the non-primary thread is the one initiating the
    // exit. Use the syscall to set a non-zero exit code, which will be
    // overridden later by the exit thread.
    syscall(SYS_exit, 1);
    abort();
}
