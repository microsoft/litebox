// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that CPU-time clocks, getrusage, times, wait4, and SIGCHLD report the CPU time used by a
// process and by the descendants it waited for.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// CPU time each process burns.
#define WORK_NS 50000000LL

static int failures;

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if (!(condition)) {                                                                 \
            printf("FAIL line %d: %s\n", __LINE__, #condition);                             \
            failures++;                                                                     \
        }                                                                                   \
    } while (0)

static long long clock_ns(clockid_t clock) {
    struct timespec time;
    if (clock_gettime(clock, &time) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return time.tv_sec * 1000000000LL + time.tv_nsec;
}

static long long timeval_ns(struct timeval time) {
    return time.tv_sec * 1000000000LL + time.tv_usec * 1000LL;
}

static long long rusage_ns(const struct rusage *usage) {
    return timeval_ns(usage->ru_utime) + timeval_ns(usage->ru_stime);
}

static long long usage_ns(int who) {
    struct rusage usage;
    if (getrusage(who, &usage) != 0) {
        perror("getrusage");
        exit(1);
    }
    return rusage_ns(&usage);
}

// Converts nanoseconds to clock ticks, rounding down.
static long long ticks(long long ns) {
    return ns * sysconf(_SC_CLK_TCK) / 1000000000LL;
}

// Burns `WORK_NS` of the calling thread's CPU time.
static void burn(void) {
    long long start = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    volatile unsigned long sink = 0;
    while (clock_ns(CLOCK_THREAD_CPUTIME_ID) - start < WORK_NS) {
        for (int i = 0; i < 10000; i++) {
            sink += i;
        }
    }
}

static pid_t fork_flushed(void) {
    fflush(stdout);
    return fork();
}

static pid_t wait_child(pid_t child, int *status, struct rusage *usage) {
    pid_t waited;
    do {
        waited = wait4(child, status, 0, usage);
    } while (waited < 0 && errno == EINTR);
    return waited;
}

static volatile sig_atomic_t sigchld_ticks = -1;

static void on_sigchld(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    sigchld_ticks = info->si_utime + info->si_stime;
}

// Waits up to a second for the SIGCHLD handler to run.
static void await_sigchld(void) {
    for (int i = 0; i < 1000 && sigchld_ticks < 0; i++) {
        usleep(1000);
    }
}

// Burns CPU time, then forks a grandchild that does too and waits for it, and writes the CPU time
// it used and the CPU time its children used to `report`.
static void run_child(int report) {
    burn();
    pid_t grandchild = fork_flushed();
    if (grandchild < 0) {
        perror("fork");
        _exit(1);
    }
    if (grandchild == 0) {
        burn();
        _exit(0);
    }
    int status;
    struct rusage usage;
    if (wait_child(grandchild, &status, &usage) != grandchild || !WIFEXITED(status)) {
        _exit(1);
    }
    long long times[2] = {usage_ns(RUSAGE_SELF), usage_ns(RUSAGE_CHILDREN)};
    if (rusage_ns(&usage) != times[1] ||
        write(report, times, sizeof times) != (ssize_t)sizeof times) {
        _exit(1);
    }
    _exit(0);
}

int main(void) {
    burn();
    CHECK(clock_ns(CLOCK_THREAD_CPUTIME_ID) >= WORK_NS);
    CHECK(clock_ns(CLOCK_PROCESS_CPUTIME_ID) >= WORK_NS);
    CHECK(usage_ns(RUSAGE_THREAD) >= WORK_NS);
    CHECK(usage_ns(RUSAGE_SELF) >= WORK_NS);
    CHECK(usage_ns(RUSAGE_CHILDREN) == 0);
    struct timespec resolution;
    CHECK(clock_getres(CLOCK_THREAD_CPUTIME_ID, &resolution) == 0 && resolution.tv_sec == 0 &&
          resolution.tv_nsec > 0);
    struct tms tms;
    CHECK(times(&tms) != (clock_t)-1);
    // Each of two truncated fields loses less than a tick.
    CHECK(tms.tms_utime + tms.tms_stime >= ticks(WORK_NS) - 1);
    CHECK(tms.tms_cutime == 0 && tms.tms_cstime == 0);

    struct sigaction action = {.sa_sigaction = on_sigchld, .sa_flags = SA_SIGINFO | SA_RESTART};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) != 0) {
        perror("sigaction");
        return 1;
    }
    int report[2];
    if (pipe(report) != 0) {
        perror("pipe");
        return 1;
    }
    pid_t child = fork_flushed();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        close(report[0]);
        run_child(report[1]);
    }
    close(report[1]);
    long long reported[2];
    CHECK(read(report[0], reported, sizeof reported) == (ssize_t)sizeof reported);
    int status;
    struct rusage usage;
    CHECK(wait_child(child, &status, &usage) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);

    // The child's usage covers what it used until it reported and its grandchild's.
    long long child_ns = rusage_ns(&usage);
    CHECK(reported[1] >= WORK_NS);
    CHECK(child_ns >= reported[0] + reported[1]);
    CHECK(usage_ns(RUSAGE_CHILDREN) == child_ns);
    CHECK(times(&tms) != (clock_t)-1);
    CHECK(tms.tms_cutime + tms.tms_cstime >= ticks(child_ns) - 1);
    await_sigchld();
    // Like Linux, SIGCHLD reports only the child's own usage.
    long long own_ns = child_ns - reported[1];
    CHECK(sigchld_ticks >= ticks(own_ns) - 1 && sigchld_ticks <= ticks(own_ns));

    printf("cpu-time failures=%d\n", failures);
    return failures != 0;
}
