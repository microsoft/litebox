// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Forks while sibling threads run guest code, block reading a pipe, and sleep, and forks from
// several threads at once, checking that each child copies memory the counting thread could have
// left and that the siblings go on unaffected.

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FORKERS 2
#define FORKS_PER_FORKER 3

// Forks by system call, bypassing glibc. AArch64 has no `fork`, so use `clone(SIGCHLD)`.
static pid_t raw_fork(void) {
#ifdef SYS_fork
    return (pid_t)syscall(SYS_fork);
#else
    return (pid_t)syscall(SYS_clone, SIGCHLD, 0, NULL, NULL, 0);
#endif
}

// Two counters far enough apart that copying memory reaches one long after the other.
static struct {
    volatile unsigned long head;
    char gap[4 * 1024 * 1024];
    volatile unsigned long tail;
} counters;
static atomic_int stop;
static int reader_pipe[2];
static atomic_int forkers_ready;

static void *count_up(void *arg) {
    (void)arg;
    for (unsigned long value = 1; !atomic_load_explicit(&stop, memory_order_relaxed); value++) {
        counters.head = value;
        counters.tail = value;
    }
    return NULL;
}

// Returns whether the counters hold values `count_up` could have left between two instructions.
static int counters_consistent(void) {
    unsigned long head = counters.head;
    unsigned long tail = counters.tail;
    return head == tail || head == tail + 1;
}

static void *read_pipe(void *arg) {
    (void)arg;
    char byte = 0;
    ssize_t count;
    do {
        count = read(reader_pipe[0], &byte, 1);
    } while (count == -1 && errno == EINTR);
    return (void *)(long)(count == 1 && byte == 'x');
}

static void *sleep_through_forks(void *arg) {
    (void)arg;
    struct timespec duration = {.tv_sec = 0, .tv_nsec = 300 * 1000 * 1000};
    return (void *)(long)(nanosleep(&duration, NULL) == 0);
}

static int wait_exit_code(pid_t child) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Forks by system call, as glibc's fork() holds process-wide locks that would keep the forkers
// from forking at once. Each child only reads memory and exits.
static void *fork_repeatedly(void *arg) {
    (void)arg;
    long failures = 0;
    for (int i = 0; i < FORKS_PER_FORKER; i++) {
        // Spin, rather than block, so the forkers make the system call at the same time.
        atomic_fetch_add(&forkers_ready, 1);
        while (atomic_load(&forkers_ready) < (i + 1) * FORKERS) {
        }
        pid_t child = raw_fork();
        if (child == 0) {
            _exit(counters_consistent() ? 0 : 1);
        }
        failures += child < 0 || wait_exit_code(child) != 0;
    }
    return (void *)failures;
}

int main(void) {
    pthread_t counter, reader, sleeper, forkers[FORKERS];
    if (pipe(reader_pipe) != 0 || pthread_create(&counter, NULL, count_up, NULL) != 0 ||
        pthread_create(&reader, NULL, read_pipe, NULL) != 0 ||
        pthread_create(&sleeper, NULL, sleep_through_forks, NULL) != 0) {
        printf("setup-error\n");
        return 2;
    }
    // Let the counter get going and the reader and the sleeper block.
    while (counters.tail < 1000) {
    }
    struct timespec settle = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
    nanosleep(&settle, NULL);

    pid_t child = fork();
    if (child == 0) {
        _exit(counters_consistent() ? 7 : 1);
    }
    int code = child < 0 ? -1 : wait_exit_code(child);

    // Forkers pause each other, and the other threads, as they fork at once.
    long failures = 0;
    for (int i = 0; i < FORKERS; i++) {
        if (pthread_create(&forkers[i], NULL, fork_repeatedly, NULL) != 0) {
            printf("setup-error\n");
            return 3;
        }
    }
    for (int i = 0; i < FORKERS; i++) {
        void *forker_failures;
        pthread_join(forkers[i], &forker_failures);
        failures += (long)forker_failures;
    }

    // The siblings go on after the forks.
    unsigned long last = counters.tail;
    while (counters.tail == last) {
    }
    void *read_ok, *slept;
    if (write(reader_pipe[1], "x", 1) != 1) {
        printf("write-error\n");
        return 4;
    }
    pthread_join(reader, &read_ok);
    pthread_join(sleeper, &slept);
    atomic_store(&stop, 1);
    pthread_join(counter, NULL);
    printf("threads-fork code=%d failures=%ld read=%ld slept=%ld\n", code, failures, (long)read_ok,
           (long)slept);
    return 0;
}
