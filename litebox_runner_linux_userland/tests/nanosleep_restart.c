// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that a relative nanosleep interrupted by a signal that runs no handler restarts through
// restart_syscall for its remaining time, while a handler interrupts it with EINTR, and that
// restart_syscall fails with EINTR unless an interrupted sleep left something to resume.

#define _GNU_SOURCE
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>

#include "helpers.h"

#define SLEEP_NS (300L * 1000 * 1000)
#define SIGNAL_DELAY_MS 50
#define CLOCK_SLACK_NS (5L * 1000 * 1000)
// Linux's KTIME_MAX in seconds: the latest time since boot a sleep can last until.
#define MAX_SLEEP_SEC (LLONG_MAX / 1000000000LL)

static long elapsed_ns(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000000000L + (now.tv_nsec - start->tv_nsec);
}

struct sleep_result {
    struct timespec request;
    atomic_int ready;
    int ret;
    int err;
    long elapsed;
    struct timespec remain;
    // restart_syscall right after the sleep, then after a new uninterrupted sleep.
    int restart_ret;
    int restart_err;
    int fresh_restart_ret;
    int fresh_restart_err;
};

static void call_restart_syscall(int *ret, int *err) {
    errno = 0;
    *ret = (int)syscall(SYS_restart_syscall);
    *err = errno;
}

static void *sleeper(void *arg) {
    struct sleep_result *result = arg;
    struct timespec start;
    result->remain = (struct timespec){.tv_sec = -1, .tv_nsec = -1};
    clock_gettime(CLOCK_MONOTONIC, &start);
    atomic_store(&result->ready, 1);
    result->ret = (int)syscall(SYS_nanosleep, &result->request, &result->remain);
    result->err = errno;
    result->elapsed = elapsed_ns(&start);
    // An interrupted sleep can be resumed again once finished, unless a handler returned
    // through rt_sigreturn.
    call_restart_syscall(&result->restart_ret, &result->restart_err);
    // A new sleep leaves nothing to resume.
    struct timespec instant = {.tv_sec = 0, .tv_nsec = 1000};
    TEST_ASSERT(nanosleep(&instant, NULL) == 0, "short nanosleep");
    call_restart_syscall(&result->fresh_restart_ret, &result->fresh_restart_err);
    return NULL;
}

static void handle_signal(int signal) { (void)signal; }

static void set_handler(int signal, void (*handler)(int), int flags) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    action.sa_flags = flags;
    sigemptyset(&action.sa_mask);
    TEST_ASSERT(sigaction(signal, &action, NULL) == 0, "sigaction");
}

static void expect_eintr(int ret, int err, const char *what) {
    if (ret != -1 || err != EINTR) {
        printf("FAIL: %s: ret=%d errno=%d, expected -1 EINTR\n", what, ret, err);
        exit(1);
    }
}

// Sends `signal` to the process while the main thread blocks it, so a sleeper sleeping for
// `request` takes it, and returns how the sleep went.
static struct sleep_result signal_sleeper(int signal, struct timespec request) {
    struct sleep_result result = {.request = request};
    pthread_t thread;
    TEST_ASSERT(pthread_create(&thread, NULL, sleeper, &result) == 0, "pthread_create");
    // Block the signal only after creating the sleeper, which would otherwise inherit the mask.
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, signal);
    pthread_sigmask(SIG_BLOCK, &set, &old);
    while (!atomic_load(&result.ready)) {
        sched_yield();
    }
    sleep_ms(SIGNAL_DELAY_MS);
    TEST_ASSERT(kill(getpid(), signal) == 0, "kill");
    pthread_join(thread, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (result.ret == 0 && result.remain.tv_sec == -1) {
        printf("FAIL: signal %d missed the sleep\n", signal);
        exit(1);
    }
    expect_eintr(result.fresh_restart_ret, result.fresh_restart_err,
                 "restart_syscall after a new sleep");
    return result;
}

static void test_restart_syscall_fails_without_interrupted_sleep(void) {
    int ret, err;
    call_restart_syscall(&ret, &err);
    expect_eintr(ret, err, "restart_syscall at start");
    struct timespec duration = {.tv_sec = 0, .tv_nsec = 1000};
    TEST_ASSERT(nanosleep(&duration, NULL) == 0, "nanosleep");
    call_restart_syscall(&ret, &err);
    expect_eintr(ret, err, "restart_syscall after an uninterrupted sleep");
}

// SIGCHLD is ignored by default, but the main thread blocks it, so it is queued rather than
// discarded, and wakes the sleeper, which discards it and must sleep on.
static void test_ignored_signal_restarts_sleep(void) {
    struct sleep_result result =
        signal_sleeper(SIGCHLD, (struct timespec){.tv_sec = 0, .tv_nsec = SLEEP_NS});
    if (result.ret != 0) {
        printf("FAIL: ignored signal: nanosleep ret=%d errno=%d, expected 0\n", result.ret,
               result.err);
        exit(1);
    }
    // Allow for coarse clocks; ending early by the 250 ms the signal left would still fail.
    if (result.elapsed < SLEEP_NS - CLOCK_SLACK_NS) {
        printf("FAIL: ignored signal: slept %ld ns, expected at least %ld\n", result.elapsed,
               SLEEP_NS);
        exit(1);
    }
    // The interruption reported the time left, though the sleep then went on.
    if (result.remain.tv_sec != 0 || result.remain.tv_nsec <= 0 ||
        result.remain.tv_nsec >= SLEEP_NS) {
        printf("FAIL: ignored signal: remain %ld.%09ld\n", (long)result.remain.tv_sec,
               result.remain.tv_nsec);
        exit(1);
    }
    // Resuming the finished sleep returns at once.
    if (result.restart_ret != 0) {
        printf("FAIL: ignored signal: restart_syscall ret=%d errno=%d, expected 0\n",
               result.restart_ret, result.restart_err);
        exit(1);
    }
}

// A handler interrupts the sleep, which reports the time left, whether or not it has
// SA_RESTART.
static void test_handler_interrupts_sleep(int flags) {
    set_handler(SIGUSR1, handle_signal, flags);
    struct sleep_result result =
        signal_sleeper(SIGUSR1, (struct timespec){.tv_sec = 0, .tv_nsec = SLEEP_NS});
    set_handler(SIGUSR1, SIG_DFL, 0);

    expect_eintr(result.ret, result.err, "handler: nanosleep");
    if (result.remain.tv_sec != 0 || result.remain.tv_nsec <= 0 ||
        result.remain.tv_nsec >= SLEEP_NS) {
        printf("FAIL: handler flags=%#x: remain %ld.%09ld\n", flags, (long)result.remain.tv_sec,
               result.remain.tv_nsec);
        exit(1);
    }
    expect_eintr(result.restart_ret, result.restart_err, "handler: restart_syscall");
}

// A sleep too long to end lasts until KTIME_MAX since boot, so its interruption reports the time
// left until then.
static void test_unbounded_sleep_reports_time_left(void) {
    set_handler(SIGUSR1, handle_signal, 0);
    struct sleep_result result =
        signal_sleeper(SIGUSR1, (struct timespec){.tv_sec = LONG_MAX, .tv_nsec = 999999999});
    set_handler(SIGUSR1, SIG_DFL, 0);

    expect_eintr(result.ret, result.err, "unbounded sleep: nanosleep");
    if (result.remain.tv_sec <= MAX_SLEEP_SEC / 2 || result.remain.tv_sec > MAX_SLEEP_SEC) {
        printf("FAIL: unbounded sleep: remain %ld.%09ld\n", (long)result.remain.tv_sec,
               result.remain.tv_nsec);
        exit(1);
    }
}

int main(void) {
    printf("Testing nanosleep restart...\n");
    test_restart_syscall_fails_without_interrupted_sleep();
    test_ignored_signal_restarts_sleep();
    test_handler_interrupts_sleep(0);
    test_handler_interrupts_sleep(SA_RESTART);
    test_unbounded_sleep_reports_time_left();
    printf("All nanosleep restart tests passed.\n");
    return 0;
}
