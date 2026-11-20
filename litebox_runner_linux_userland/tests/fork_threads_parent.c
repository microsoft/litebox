// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Forks while sibling threads run guest code, block reading a pipe, and sleep, and forks from
// several threads at once, checking that each child inherits memory and the siblings go on.

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

static volatile struct {
    unsigned long head;
    char gap[4 * 1024 * 1024];
    unsigned long tail;
} markers;
static atomic_ulong counter;
static atomic_int stop;
static int reader_pipe[2];
static atomic_int forkers_ready;

static void *count_up(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        atomic_fetch_add_explicit(&counter, 1, memory_order_relaxed);
    }
    return NULL;
}

static int inherited_markers(void) {
    return markers.head == 17 && markers.tail == 29;
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
    int result;
    do {
        result = nanosleep(&duration, &duration);
    } while (result == -1 && errno == EINTR);
    return (void *)(long)(result == 0);
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
            _exit(inherited_markers() ? 0 : 1);
        }
        failures += child < 0 || wait_exit_code(child) != 0;
    }
    return (void *)failures;
}

int main(void) {
    markers.head = 17;
    markers.tail = 29;
    pthread_t counter_thread, reader, sleeper, forkers[FORKERS];
    if (pipe(reader_pipe) != 0 || pthread_create(&counter_thread, NULL, count_up, NULL) != 0 ||
        pthread_create(&reader, NULL, read_pipe, NULL) != 0 ||
        pthread_create(&sleeper, NULL, sleep_through_forks, NULL) != 0) {
        printf("setup-error\n");
        return 2;
    }
    // Let the counter get going and the reader and the sleeper block.
    while (atomic_load_explicit(&counter, memory_order_relaxed) < 1000) {
    }
    struct timespec settle = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
    nanosleep(&settle, NULL);

    pid_t child = fork();
    if (child == 0) {
        _exit(inherited_markers() ? 7 : 1);
    }
    int code = child < 0 ? -1 : wait_exit_code(child);

    // Fork from several threads at once.
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
    unsigned long last = atomic_load_explicit(&counter, memory_order_relaxed);
    while (atomic_load_explicit(&counter, memory_order_relaxed) == last) {
    }
    void *read_ok, *slept;
    if (write(reader_pipe[1], "x", 1) != 1) {
        printf("write-error\n");
        return 4;
    }
    pthread_join(reader, &read_ok);
    pthread_join(sleeper, &slept);
    atomic_store(&stop, 1);
    pthread_join(counter_thread, NULL);
    printf("threads-fork code=%d failures=%ld read=%ld slept=%ld\n", code, failures, (long)read_ok,
           (long)slept);
    return code == 7 && failures == 0 && (long)read_ok == 1 && (long)slept == 1 ? 0 : 1;
}
