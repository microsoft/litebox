// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that a relative nanosleep interrupted by a signal that runs no handler restarts through
// restart_syscall for its remaining time, while a handler interrupts it with EINTR, and that
// restart_syscall fails with EINTR unless an interrupted sleep left something to resume.

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define SLEEP_NS (300L * 1000 * 1000)
#define SIGNAL_DELAY_NS (50L * 1000 * 1000)

static void fail(const char *what) {
    printf("FAIL: %s\n", what);
    exit(1);
}

static long elapsed_ns(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000000000L + (now.tv_nsec - start->tv_nsec);
}

static void sleep_ns(long ns) {
    struct timespec duration = {.tv_sec = 0, .tv_nsec = ns};
    while (nanosleep(&duration, &duration) == -1 && errno == EINTR) {
    }
}

struct sleep_result {
    int ret;
    int err;
    long elapsed;
    struct timespec remain;
    int restart_ret;
    int restart_err;
};

static void *sleeper(void *arg) {
    struct sleep_result *result = arg;
    struct timespec duration = {.tv_sec = 0, .tv_nsec = SLEEP_NS};
    struct timespec start;
    result->remain = (struct timespec){.tv_sec = -1, .tv_nsec = -1};
    clock_gettime(CLOCK_MONOTONIC, &start);
    result->ret = (int)syscall(SYS_nanosleep, &duration, &result->remain);
    result->err = errno;
    result->elapsed = elapsed_ns(&start);
    // An interrupted sleep can be resumed again once finished, unless a handler returned
    // through rt_sigreturn.
    errno = 0;
    result->restart_ret = (int)syscall(SYS_restart_syscall);
    result->restart_err = errno;
    return NULL;
}

static void handle_signal(int signal) { (void)signal; }

static void set_handler(int signal, void (*handler)(int), int flags) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    action.sa_flags = flags;
    sigemptyset(&action.sa_mask);
    if (sigaction(signal, &action, NULL) != 0) {
        fail("sigaction");
    }
}

static void expect_nothing_to_restart(const char *when) {
    errno = 0;
    long ret = syscall(SYS_restart_syscall);
    if (ret != -1 || errno != EINTR) {
        printf("FAIL: restart_syscall %s: ret=%ld errno=%d, expected -1 EINTR\n", when, ret,
               errno);
        exit(1);
    }
}

static void test_restart_syscall_without_restart(void) {
    expect_nothing_to_restart("at start");
    struct timespec duration = {.tv_sec = 0, .tv_nsec = 1000};
    if (nanosleep(&duration, NULL) != 0) {
        fail("nanosleep");
    }
    expect_nothing_to_restart("after an uninterrupted sleep");
}

// SIGCHLD is ignored by default, but the main thread blocks it, so it is queued rather than
// discarded, and wakes the sleeper, which discards it and must sleep on.
// Sends `signal` to the process while the main thread blocks it, so the sleeper takes it, and
// returns how the sleep went.
static struct sleep_result signal_sleeper(int signal) {
    struct sleep_result result;
    pthread_t thread;
    if (pthread_create(&thread, NULL, sleeper, &result) != 0) {
        fail("pthread_create");
    }
    // Block the signal only after creating the sleeper, which would otherwise inherit the mask.
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, signal);
    pthread_sigmask(SIG_BLOCK, &set, &old);
    sleep_ns(SIGNAL_DELAY_NS);
    if (kill(getpid(), signal) != 0) {
        fail("kill");
    }
    pthread_join(thread, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    return result;
}

static void test_ignored_signal_restarts_sleep(void) {
    struct sleep_result result = signal_sleeper(SIGCHLD);

    if (result.ret != 0) {
        printf("FAIL: ignored signal: nanosleep ret=%d errno=%d, expected 0\n", result.ret,
               result.err);
        exit(1);
    }
    if (result.elapsed < SLEEP_NS - SIGNAL_DELAY_NS / 2) {
        printf("FAIL: ignored signal: slept %ld ns, expected about %ld\n", result.elapsed,
               SLEEP_NS);
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
    struct sleep_result result = signal_sleeper(SIGUSR1);
    set_handler(SIGUSR1, SIG_DFL, 0);

    if (result.ret != -1 || result.err != EINTR) {
        printf("FAIL: handler flags=%#x: nanosleep ret=%d errno=%d, expected -1 EINTR\n", flags,
               result.ret, result.err);
        exit(1);
    }
    if (result.remain.tv_sec != 0 || result.remain.tv_nsec <= 0 ||
        result.remain.tv_nsec >= SLEEP_NS) {
        printf("FAIL: handler flags=%#x: remain %ld.%09ld\n", flags, (long)result.remain.tv_sec,
               result.remain.tv_nsec);
        exit(1);
    }
    if (result.restart_ret != -1 || result.restart_err != EINTR) {
        printf("FAIL: handler flags=%#x: restart_syscall ret=%d errno=%d, expected -1 EINTR\n",
               flags, result.restart_ret, result.restart_err);
        exit(1);
    }
}

int main(void) {
    printf("Testing nanosleep restart...\n");
    test_restart_syscall_without_restart();
    test_ignored_signal_restarts_sleep();
    test_handler_interrupts_sleep(0);
    test_handler_interrupts_sleep(SA_RESTART);
    printf("All nanosleep restart tests passed.\n");
    return 0;
}
