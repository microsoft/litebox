// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Threads of one process running at once on different CPUs, and the TLB
// shootdowns that keep them coherent; needs at least two CPUs. Each mode (the
// first argument) prints "MODE: ok"; see smp.json.
// - "parallel": two threads spin, each counting how often the other's counter
//   advanced between two of its own steps at most GAP_US apart (on one CPU,
//   it advances only while this one is preempted, a gap of about a slice):
//   both must count many.
// - "mprotect": a thread keeps writing a page, running at once with the main
//   thread (as in "parallel"), so its CPU caches the translation, until the
//   main thread makes the page read-only and raises a flag: the thread's next
//   write must fault (SIGSEGV).
// - "munmap": as "mprotect", with reads, and munmap.
// - "upgrade": as "mprotect", but the thread reads the read-only page until
//   the main thread makes it writable (which needs no shootdown: a write
//   through a stale read-only translation faults, and the kernel finds the
//   page writable), then writes it: that must not fault.
// - "remap": as "munmap", but the main thread replaces the page (MAP_FIXED)
//   with one holding the next generation, over and over, each time handing it
//   to the thread, which must read that generation there: a stale
//   translation would read another frame (e.g., the old generation's).
// - "fork": a thread keeps writing a counter to a page as the main thread
//   forks: the child must see the page as it was at the fork, unchanged over
//   50 ms, and not past what the parent saw once the fork returned. (The
//   runner pauses the thread across the fork, ending its run, and so its
//   stale translations, before the copy: this does not test the copy's
//   shootdown of other CPUs' writable translations.)
// - "cow": as "munmap", but the page is shared with a waiting child, and the
//   main thread writes it (a copy): the thread's next read must see the write.
// - "stress": threads map, fill, protect, check and unmap pages of their own,
//   and count in a shared region they all fault in, at once, for a while;
//   the counts must add up. Stress only: no thread uses another's pages, so
//   no shootdown is checked.

#include <limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__,     \
                    __LINE__, #cond);                                  \
            exit(1);                                                   \
        }                                                              \
    } while (0)

#define PAGE 4096
#define WORDS (PAGE / sizeof(unsigned long))
// At most this far apart, two steps of a thread see another thread advance
// in between only if both run at once.
#define GAP_US 200
// How many sightings of that show that they do.
#define OVERLAPS 1000
// How long the other modes wait for them.
#define OVERLAP_MS 2000
// How long "parallel" spins.
#define PARALLEL_MS 200

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0) {
    }
}

static double ticks_per_us;

// Calibrates the TSC, which the spins read, as the clock costs a call into
// the runner.
static void calibrate(void) {
    unsigned long long ticks = __rdtsc();
    long long start = now_us();
    sleep_ms(5);
    ticks_per_us = (double)(__rdtsc() - ticks) / (double)(now_us() - start);
}

// Each thread's steps so far, which the other watches.
static _Atomic unsigned long progress[2];

// Steps `progress[self]` while watching `progress[!self]`, for at most `ms`
// or until that advanced between two of its steps at most GAP_US apart
// `want` times; returns how many times it did. Timed around both reads, so
// that a preemption between them makes the gap.
static long overlap(int self, long want, long long ms) {
    unsigned long long gap = (unsigned long long)(GAP_US * ticks_per_us);
    unsigned long long end = __rdtsc() + (unsigned long long)(ms * 1000 * ticks_per_us);
    unsigned long long before = __rdtsc();
    unsigned long seen = atomic_load_explicit(&progress[!self], memory_order_relaxed);
    unsigned long steps = 0;
    long overlaps = 0;
    while (overlaps < want && before < end) {
        atomic_store_explicit(&progress[self], ++steps, memory_order_relaxed);
        unsigned long long next = __rdtsc();
        unsigned long now_seen = atomic_load_explicit(&progress[!self], memory_order_relaxed);
        if (now_seen != seen && __rdtsc() - before <= gap) {
            overlaps++;
        }
        seen = now_seen;
        before = next;
    }
    return overlaps;
}

static long spun[2];

static void *spin(void *arg) {
    int self = (int)(long)arg;
    spun[self] = overlap(self, LONG_MAX, PARALLEL_MS);
    return NULL;
}

static int parallel_mode(void) {
    pthread_t threads[2];
    for (long i = 0; i < 2; i++) {
        CHECK(pthread_create(&threads[i], NULL, spin, (void *)i) == 0);
    }
    for (int i = 0; i < 2; i++) {
        CHECK(pthread_join(threads[i], NULL) == 0);
    }
    if (spun[0] < OVERLAPS || spun[1] < OVERLAPS) {
        fprintf(stderr, "parallel: overlaps %ld and %ld\n", spun[0], spun[1]);
        return 1;
    }
    return 0;
}

// The page the other thread works on, which both threads access at once, and
// the flag (in another page) that the main thread raises once it changed the
// page.
static _Atomic unsigned long *target;
static _Atomic int flag;

// Maps `target`, read-write and populated.
static void map_target(void) {
    void *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    target = page;
    target[0] = 1;
}

// Starts `run` in another thread, once it runs at once with this one.
static pthread_t start_overlapping(void *(*run)(void *)) {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, run, NULL) == 0);
    CHECK(overlap(0, OVERLAPS, OVERLAP_MS) == OVERLAPS);
    return thread;
}

static sigjmp_buf fault_jump;
static _Atomic int faulted;

static void on_fault(int signal) {
    (void)signal;
    siglongjmp(fault_jump, 1);
}

// Writes, or reads, `target` until the flag, and once more after: that
// access must fault.
static void *access_target(int write) {
    unsigned long steps = 0;
    if (sigsetjmp(fault_jump, 1) != 0) {
        atomic_store(&faulted, 1);
        return NULL;
    }
    while (!atomic_load(&flag)) {
        if (write) {
            target[0] = steps;
        } else {
            (void)target[0];
        }
        atomic_store_explicit(&progress[1], ++steps, memory_order_relaxed);
    }
    if (write) {
        target[0] = steps;
    } else {
        (void)target[0];
    }
    return NULL;
}

static void *write_target(void *arg) {
    (void)arg;
    return access_target(1);
}

static void *read_target(void *arg) {
    (void)arg;
    return access_target(0);
}

// "munmap" if `unmap`, else "mprotect".
static int revoke_mode(int unmap) {
    struct sigaction action = {.sa_handler = on_fault};
    CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
    map_target();
    pthread_t thread = start_overlapping(unmap ? read_target : write_target);
    if (unmap) {
        CHECK(munmap((void *)target, PAGE) == 0);
    } else {
        CHECK(mprotect((void *)target, PAGE, PROT_READ) == 0);
    }
    atomic_store(&flag, 1);
    CHECK(pthread_join(thread, NULL) == 0);
    if (!atomic_load(&faulted)) {
        fprintf(stderr, "%s: no fault after the flag\n", unmap ? "munmap" : "mprotect");
        return 1;
    }
    return 0;
}

// Reads `target` until the flag, then writes it.
static void *read_then_write_target(void *arg) {
    (void)arg;
    unsigned long steps = 0;
    if (sigsetjmp(fault_jump, 1) != 0) {
        atomic_store(&faulted, 1);
        return NULL;
    }
    while (!atomic_load(&flag)) {
        (void)target[0];
        atomic_store_explicit(&progress[1], ++steps, memory_order_relaxed);
    }
    target[0] = 2;
    return NULL;
}

static int upgrade_mode(void) {
    struct sigaction action = {.sa_handler = on_fault};
    CHECK(sigaction(SIGSEGV, &action, NULL) == 0);
    map_target();
    CHECK(mprotect((void *)target, PAGE, PROT_READ) == 0);
    pthread_t thread = start_overlapping(read_then_write_target);
    CHECK(mprotect((void *)target, PAGE, PROT_READ | PROT_WRITE) == 0);
    atomic_store(&flag, 1);
    CHECK(pthread_join(thread, NULL) == 0);
    if (atomic_load(&faulted)) {
        fprintf(stderr, "upgrade: the write faulted\n");
        return 1;
    }
    CHECK(target[0] == 2);
    return 0;
}

#define GENERATIONS 200

// The generation the main thread put in `target`, and the last the thread
// read there.
static _Atomic unsigned long published, acknowledged;
// The first generation the thread did not read there, if any, and what it
// read instead.
static unsigned long wrong_generation, wrong_read;

// Reads `target` until the main thread publishes a generation, then checks
// that it holds it, and acknowledges it, until the last one; makes no call,
// which could switch its CPU's address space, and so flush its TLB.
static void *read_generations(void *arg) {
    (void)arg;
    unsigned long steps = 0;
    for (unsigned long generation = 2; generation <= GENERATIONS; generation++) {
        while (atomic_load(&published) != generation) {
            (void)target[0];
            atomic_store_explicit(&progress[1], ++steps, memory_order_relaxed);
        }
        unsigned long found = target[0];
        if (found != generation && wrong_generation == 0) {
            wrong_generation = generation;
            wrong_read = found;
        }
        atomic_store(&acknowledged, generation);
    }
    return NULL;
}

static int remap_mode(void) {
    map_target();
    // A page per generation, faulted in after each remap, to take the old
    // frame if the kernel reuses the last one freed first.
    unsigned long *decoys = mmap(NULL, (GENERATIONS + 1) * PAGE, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(decoys != MAP_FAILED);
    pthread_t thread = start_overlapping(read_generations);
    for (unsigned long generation = 2; generation <= GENERATIONS; generation++) {
        CHECK(mmap((void *)target, PAGE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == (void *)target);
        decoys[generation * WORDS] = ULONG_MAX;
        target[0] = generation;
        atomic_store(&published, generation);
        while (atomic_load(&acknowledged) != generation) {
        }
    }
    CHECK(pthread_join(thread, NULL) == 0);
    if (wrong_generation != 0) {
        fprintf(stderr, "remap: read %lu, not generation %lu\n", wrong_read, wrong_generation);
        return 1;
    }
    return 0;
}

static void *count_into_target(void *arg) {
    (void)arg;
    unsigned long steps = 0;
    while (!atomic_load(&flag)) {
        target[0] = ++steps;
        atomic_store_explicit(&progress[1], steps, memory_order_relaxed);
    }
    return NULL;
}

// Reaps `child`; whether it exited with 0.
static int reap(pid_t child) {
    int status;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int fork_mode(void) {
    map_target();
    int fds[2];
    CHECK(pipe(fds) == 0);
    pthread_t thread = start_overlapping(count_into_target);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        close(fds[0]);
        unsigned long values[2];
        values[0] = target[0];
        sleep_ms(50);
        values[1] = target[0];
        _exit(write(fds[1], values, sizeof values) == (ssize_t)sizeof values ? 0 : 1);
    }
    // So that the read below ends if the child dies first.
    close(fds[1]);
    // At least what the child's page holds: it was copied before the fork
    // returned, and the thread's counter only grows.
    unsigned long parent = target[0];
    atomic_store(&flag, 1);
    CHECK(pthread_join(thread, NULL) == 0);
    unsigned long values[2];
    CHECK(read(fds[0], values, sizeof values) == (ssize_t)sizeof values);
    CHECK(reap(child));
    if (values[0] != values[1] || values[0] > parent) {
        fprintf(stderr, "fork: the child saw %lu, then %lu; the parent %lu\n", values[0],
                values[1], parent);
        return 1;
    }
    return 0;
}

static unsigned long last_read;

static void *read_until_flag(void *arg) {
    (void)arg;
    unsigned long steps = 0;
    while (!atomic_load(&flag)) {
        (void)target[0];
        atomic_store_explicit(&progress[1], ++steps, memory_order_relaxed);
    }
    last_read = target[0];
    return NULL;
}

static int cow_mode(void) {
    map_target();
    int fds[2];
    CHECK(pipe(fds) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        // Keeps the page shared until the parent closes the pipe.
        char byte;
        close(fds[1]);
        _exit(read(fds[0], &byte, 1) == 0 ? 0 : 1);
    }
    close(fds[0]);
    pthread_t thread = start_overlapping(read_until_flag);
    target[0] = 2;
    atomic_store(&flag, 1);
    CHECK(pthread_join(thread, NULL) == 0);
    close(fds[1]);
    CHECK(reap(child));
    if (last_read != 2) {
        fprintf(stderr, "cow: read %lu after the write\n", last_read);
        return 1;
    }
    return 0;
}

#define STRESS_THREADS 4
#define STRESS_MS 500
#define SHARED_PAGES 64
#define PRIVATE_PAGES 8

// A slot per thread in each page.
static volatile unsigned long *shared;
static unsigned long rounds[STRESS_THREADS];

static void *stress(void *arg) {
    long self = (long)arg;
    long long end = now_us() + STRESS_MS * 1000;
    for (unsigned long round = 0; now_us() < end; round++) {
        unsigned long *mine = mmap(NULL, PRIVATE_PAGES * PAGE, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(mine != MAP_FAILED);
        for (unsigned long page = 0; page < PRIVATE_PAGES; page++) {
            mine[page * WORDS] = self << 48 | round << 8 | page;
        }
        CHECK(mprotect(mine, PRIVATE_PAGES * PAGE, PROT_READ) == 0);
        for (unsigned long page = 0; page < PRIVATE_PAGES; page++) {
            CHECK(mine[page * WORDS] == (self << 48 | round << 8 | page));
        }
        CHECK(munmap(mine, PRIVATE_PAGES * PAGE) == 0);
        for (unsigned long page = 0; page < SHARED_PAGES; page++) {
            shared[page * WORDS + self]++;
        }
        rounds[self] = round + 1;
    }
    return NULL;
}

static int stress_mode(void) {
    void *region = mmap(NULL, SHARED_PAGES * PAGE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(region != MAP_FAILED);
    shared = region;
    pthread_t threads[STRESS_THREADS];
    for (long i = 0; i < STRESS_THREADS; i++) {
        CHECK(pthread_create(&threads[i], NULL, stress, (void *)i) == 0);
    }
    for (int i = 0; i < STRESS_THREADS; i++) {
        CHECK(pthread_join(threads[i], NULL) == 0);
    }
    for (int i = 0; i < STRESS_THREADS; i++) {
        CHECK(rounds[i] > 0);
        for (unsigned long page = 0; page < SHARED_PAGES; page++) {
            CHECK(shared[page * WORDS + i] == rounds[i]);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *mode = argc >= 2 ? argv[1] : "";
    calibrate();
    int result;
    if (strcmp(mode, "parallel") == 0) {
        result = parallel_mode();
    } else if (strcmp(mode, "mprotect") == 0) {
        result = revoke_mode(0);
    } else if (strcmp(mode, "munmap") == 0) {
        result = revoke_mode(1);
    } else if (strcmp(mode, "upgrade") == 0) {
        result = upgrade_mode();
    } else if (strcmp(mode, "remap") == 0) {
        result = remap_mode();
    } else if (strcmp(mode, "fork") == 0) {
        result = fork_mode();
    } else if (strcmp(mode, "cow") == 0) {
        result = cow_mode();
    } else if (strcmp(mode, "stress") == 0) {
        result = stress_mode();
    } else {
        fprintf(stderr, "usage: %s parallel|mprotect|munmap|upgrade|remap|fork|cow|stress\n",
                argv[0]);
        return 2;
    }
    if (result == 0) {
        printf("%s: ok\n", mode);
    }
    return result;
}
