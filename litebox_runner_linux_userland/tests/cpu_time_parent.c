// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that CPU-time clocks, including those from clock_getcpuclockid and pthread_getcpuclockid,
// getrusage, times, wait4, and SIGCHLD report the CPU time used by a process and by the descendants
// it waited for.

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <pthread.h>
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
// TEMPORARY (cpu-time-stress branch): the SIGCHLD fields, for the debug dump.
static volatile long sigchld_utime = -1, sigchld_stime = -1, sigchld_pid = -1, sigchld_code = -1;

static void on_sigchld(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    sigchld_utime = info->si_utime;
    sigchld_stime = info->si_stime;
    sigchld_pid = info->si_pid;
    sigchld_code = info->si_code;
    sigchld_ticks = info->si_utime + info->si_stime;
}

// TEMPORARY (cpu-time-stress branch): debug dump helpers.
static long long monotonic_ns(void) { return clock_ns(CLOCK_MONOTONIC); }

static void dump_rusage(const char *what, const struct rusage *usage) {
    printf("DEBUG %s: utime=%lld stime=%lld total=%lld ns\n", what, timeval_ns(usage->ru_utime),
           timeval_ns(usage->ru_stime), rusage_ns(usage));
}

static void dump_getrusage(const char *what, int who) {
    struct rusage usage;
    if (getrusage(who, &usage) == 0) {
        dump_rusage(what, &usage);
    }
}

// Prints `/proc/<pid>/<file>`, if any.
static void dump_proc(pid_t pid, const char *file) {
    char path[64], buffer[1024];
    snprintf(path, sizeof path, "/proc/%d/%s", (int)pid, file);
    FILE *stream = fopen(path, "r");
    if (stream == NULL) {
        printf("DEBUG %s: %s\n", path, strerror(errno));
        return;
    }
    size_t length = fread(buffer, 1, sizeof buffer - 1, stream);
    fclose(stream);
    buffer[length] = 0;
    while (length > 0 && buffer[length - 1] == '\n') {
        buffer[--length] = 0;
    }
    printf("DEBUG %s: %s\n", path, buffer);
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
    struct rusage self, children;
    getrusage(RUSAGE_SELF, &self);
    getrusage(RUSAGE_CHILDREN, &children);
    // TEMPORARY (cpu-time-stress branch): also the splits, for the debug dump.
    long long times[8] = {rusage_ns(&self),
                          rusage_ns(&children),
                          timeval_ns(self.ru_utime),
                          timeval_ns(self.ru_stime),
                          timeval_ns(children.ru_utime),
                          timeval_ns(children.ru_stime),
                          clock_ns(CLOCK_PROCESS_CPUTIME_ID),
                          monotonic_ns()};
    if (rusage_ns(&usage) != times[1] ||
        write(report, times, sizeof times) != (ssize_t)sizeof times) {
        _exit(1);
    }
    _exit(0);
}

int main(void) {
    long long start_mono = monotonic_ns();
    printf("DEBUG CLK_TCK=%ld nprocs=%ld\n", sysconf(_SC_CLK_TCK), sysconf(_SC_NPROCESSORS_ONLN));
    burn();
    CHECK(clock_ns(CLOCK_THREAD_CPUTIME_ID) >= WORK_NS);
    CHECK(clock_ns(CLOCK_PROCESS_CPUTIME_ID) >= WORK_NS);
    CHECK(usage_ns(RUSAGE_THREAD) >= WORK_NS);
    CHECK(usage_ns(RUSAGE_SELF) >= WORK_NS);
    CHECK(usage_ns(RUSAGE_CHILDREN) == 0);
    struct timespec resolution;
    CHECK(clock_getres(CLOCK_THREAD_CPUTIME_ID, &resolution) == 0 && resolution.tv_sec == 0 &&
          resolution.tv_nsec > 0);
    clockid_t clocks[3];
    CHECK(clock_getcpuclockid(0, &clocks[0]) == 0);
    CHECK(clock_getcpuclockid(getpid(), &clocks[1]) == 0);
    CHECK(pthread_getcpuclockid(pthread_self(), &clocks[2]) == 0);
    for (int i = 0; i < 3; i++) {
        CHECK(clock_ns(clocks[i]) >= WORK_NS);
    }
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
    long long reported[8] = {0};
    CHECK(read(report[0], reported, sizeof reported) == (ssize_t)sizeof reported);
    long long read_mono = monotonic_ns();
    // TEMPORARY (cpu-time-stress branch): the kernel's view of the exited, unreaped child.
    if (getenv("CPU_TIME_DEBUG") != NULL) {
        siginfo_t info = {0};
        int waited;
        do {
            waited = waitid(P_PID, child, &info, WEXITED | WNOWAIT);
        } while (waited < 0 && errno == EINTR);
        printf("DEBUG waitid(WNOWAIT)=%d utime=%ld stime=%ld code=%d status=%d\n", waited,
               (long)info.si_utime, (long)info.si_stime, info.si_code, info.si_status);
        dump_proc(child, "stat");
        dump_proc(child, "schedstat");
        dump_proc(getpid(), "stat");
        dump_proc(getpid(), "schedstat");
    }
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

    // TEMPORARY (cpu-time-stress branch): everything the checks compare.
    printf("DEBUG elapsed: to-read=%lld total=%lld ns\n", read_mono - start_mono,
           monotonic_ns() - start_mono);
    printf("DEBUG child reported: self=%lld (u=%lld s=%lld) children=%lld (u=%lld s=%lld) "
           "process-clock=%lld at-mono=%lld\n",
           reported[0], reported[2], reported[3], reported[1], reported[4], reported[5],
           reported[6], reported[7] - start_mono);
    dump_rusage("wait4 child", &usage);
    dump_getrusage("parent RUSAGE_SELF", RUSAGE_SELF);
    dump_getrusage("parent RUSAGE_CHILDREN", RUSAGE_CHILDREN);
    printf("DEBUG times: utime=%ld stime=%ld cutime=%ld cstime=%ld ticks(child_ns)=%lld\n",
           (long)tms.tms_utime, (long)tms.tms_stime, (long)tms.tms_cutime, (long)tms.tms_cstime,
           ticks(child_ns));
    printf("DEBUG sigchld: ticks=%ld utime=%ld stime=%ld pid=%ld code=%ld (child %d)\n",
           (long)sigchld_ticks, sigchld_utime, sigchld_stime, sigchld_pid, sigchld_code,
           (int)child);
    printf("DEBUG own_ns=%lld ticks(own_ns)=%lld bounds=[%lld, %lld]\n", own_ns, ticks(own_ns),
           ticks(own_ns) - 1, ticks(own_ns));
    printf("cpu-time failures=%d\n", failures);
    return failures != 0;
}
