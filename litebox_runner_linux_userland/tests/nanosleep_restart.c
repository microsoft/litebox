// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>

#include "helpers.h"

#define SLEEP_NS (300L * 1000 * 1000)
// How long ignored signals are sent at a bounded sleep, which they cannot end.
#define SIGNAL_WINDOW_MS 100
// Bounds waits for an outcome that is certain, so a broken implementation fails rather than
// hangs.
#define LIVENESS_MS (30L * 1000)
#define CLOCK_SLACK_NS (5L * 1000 * 1000)
// Linux's KTIME_MAX in seconds: the latest time since boot a sleep can last until.
#define MAX_SLEEP_SEC (LLONG_MAX / 1000000000LL)
#define UNBOUNDED {.tv_sec = LONG_MAX, .tv_nsec = 999999999}

static long elapsed_ns(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000000000L + (now.tv_nsec - start->tv_nsec);
}

struct sleep_result {
    // Whether to sleep with clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME) until `request`
    // from the start, rather than with nanosleep for `request`.
    int absolute;
    struct timespec request;
    atomic_int ready;
    // Set once the sleep returns and the sleeper blocks the test's signals.
    atomic_int done;
    int ret;
    int err;
    long elapsed;
    // Starts as {-1, -1}, so the main thread can see a relative sleep's interruption write it.
    struct timespec remain;
    // restart_syscall right after the sleep, then after a new uninterrupted sleep.
    int restart_ret;
    int restart_err;
    int fresh_restart_ret;
    int fresh_restart_err;
};

struct sleeper {
    pthread_t thread;
    sigset_t old_mask;
    struct sleep_result result;
};

static void test_signal_set(sigset_t *set) {
    sigemptyset(set);
    sigaddset(set, SIGCHLD);
    sigaddset(set, SIGUSR1);
}

static void call_restart_syscall(int *ret, int *err) {
    errno = 0;
    *ret = (int)syscall(SYS_restart_syscall);
    *err = errno;
}

static void *sleeper_main(void *arg) {
    struct sleep_result *result = arg;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    struct timespec request = result->request;
    if (result->absolute) {
        request.tv_sec += start.tv_sec;
        request.tv_nsec += start.tv_nsec;
        if (request.tv_nsec >= 1000000000L) {
            request.tv_sec++;
            request.tv_nsec -= 1000000000L;
        }
    }
    atomic_store(&result->ready, 1);
    result->ret = result->absolute ? (int)syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC,
                                                  TIMER_ABSTIME, &request, &result->remain)
                                   : (int)syscall(SYS_nanosleep, &request, &result->remain);
    result->err = errno;
    result->elapsed = elapsed_ns(&start);
    // Signals still on their way must not interrupt what follows.
    sigset_t set;
    test_signal_set(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    atomic_store(&result->done, 1);
    // An interrupted relative sleep can be resumed again once finished, unless a handler
    // returned through rt_sigreturn.
    call_restart_syscall(&result->restart_ret, &result->restart_err);
    // A new sleep leaves nothing to resume.
    struct timespec instant = {.tv_sec = 0, .tv_nsec = 1000};
    TEST_ASSERT(nanosleep(&instant, NULL) == 0, "short nanosleep");
    call_restart_syscall(&result->fresh_restart_ret, &result->fresh_restart_err);
    return NULL;
}

static void expect_eintr(int ret, int err, const char *what) {
    if (ret != -1 || err != EINTR) {
        printf("FAIL: %s: ret=%d errno=%d, expected -1 EINTR\n", what, ret, err);
        exit(1);
    }
}

// Starts a sleeper, then blocks the test's signals in the main thread, so the sleeper takes
// them, and waits until the sleeper is about to sleep.
static void start_sleeper(struct sleeper *s, int absolute, struct timespec request) {
    memset(&s->result, 0, sizeof(s->result));
    s->result.absolute = absolute;
    s->result.request = request;
    s->result.remain = (struct timespec){.tv_sec = -1, .tv_nsec = -1};
    TEST_ASSERT(pthread_create(&s->thread, NULL, sleeper_main, &s->result) == 0,
                "pthread_create");
    // Block the signals only after creating the sleeper, which would otherwise inherit the mask.
    sigset_t set;
    test_signal_set(&set);
    pthread_sigmask(SIG_BLOCK, &set, &s->old_mask);
    while (!atomic_load(&s->result.ready)) {
        sched_yield();
    }
}

// Waits for the sleeper, then takes any signals still pending, so a handler must still be
// installed for them.
static void finish_sleeper(struct sleeper *s) {
    pthread_join(s->thread, NULL);
    pthread_sigmask(SIG_SETMASK, &s->old_mask, NULL);
    expect_eintr(s->result.fresh_restart_ret, s->result.fresh_restart_err,
                 "restart_syscall after a new sleep");
}

static int is_done(void *arg) {
    struct sleep_result *result = arg;
    return atomic_load(&result->done);
}

static int remain_written(void *arg) {
    struct sleep_result *result = arg;
    return __atomic_load_n(&result->remain.tv_sec, __ATOMIC_ACQUIRE) != -1;
}

static int remain_written_or_done(void *arg) { return remain_written(arg) || is_done(arg); }

// Ends a sleep that ignored signals cannot end with a handled SIGUSR1.
static void end_sleep_with_handler(struct sleep_result *result) {
    if (!signal_until(SIGUSR1, is_done, result, LIVENESS_MS)) {
        printf("FAIL: SIGUSR1 did not end the sleep\n");
        exit(1);
    }
}

static void expect_remain_untouched(const struct sleep_result *result, const char *what) {
    if (result->remain.tv_sec != -1 || result->remain.tv_nsec != -1) {
        printf("FAIL: %s: remain %ld.%09ld, expected untouched\n", what,
               (long)result->remain.tv_sec, result->remain.tv_nsec);
        exit(1);
    }
}

static void expect_slept_through(const struct sleep_result *result, const char *what) {
    if (result->ret != 0) {
        printf("FAIL: %s: ret=%d errno=%d, expected 0\n", what, result->ret, result->err);
        exit(1);
    }
    // Allow for coarse clocks.
    if (result->elapsed < SLEEP_NS - CLOCK_SLACK_NS) {
        printf("FAIL: %s: slept %ld ns, expected at least %ld\n", what, result->elapsed,
               SLEEP_NS);
        exit(1);
    }
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
// discarded, and interrupts the sleeper, which discards it and must sleep on. A sleep that never
// ends on its own shows this without depending on timing: after each interruption, which writes
// `remain`, the main thread resets `remain`, so another write shows the sleep went on, now
// resumed through restart_syscall. A handler then interrupts the sleep, whether or not it has
// SA_RESTART.
static void test_ignored_signals_never_end_sleep(int flags) {
    set_handler(SIGUSR1, handle_signal, flags);
    static struct sleeper s;
    start_sleeper(&s, 0, (struct timespec)UNBOUNDED);
    for (int interruption = 1; interruption <= 3; interruption++) {
        if (interruption > 1) {
            __atomic_store_n(&s.result.remain.tv_sec, -1, __ATOMIC_RELEASE);
        }
        if (!signal_until(SIGCHLD, remain_written_or_done, &s.result, LIVENESS_MS)) {
            printf("FAIL: ignored signal: no interruption %d\n", interruption);
            exit(1);
        }
        if (is_done(&s.result)) {
            printf("FAIL: ignored signal: an interruption ended the sleep: ret=%d errno=%d\n",
                   s.result.ret, s.result.err);
            exit(1);
        }
    }
    end_sleep_with_handler(&s.result);
    finish_sleeper(&s);
    set_handler(SIGUSR1, SIG_DFL, 0);

    expect_eintr(s.result.ret, s.result.err, "handler: nanosleep");
    // Like Linux, the sleep lasts until KTIME_MAX since boot, so it reported the time left until
    // then.
    if (s.result.remain.tv_sec <= MAX_SLEEP_SEC / 2 || s.result.remain.tv_sec > MAX_SLEEP_SEC) {
        printf("FAIL: handler: remain %ld.%09ld\n", (long)s.result.remain.tv_sec,
               s.result.remain.tv_nsec);
        exit(1);
    }
    expect_eintr(s.result.restart_ret, s.result.restart_err, "handler: restart_syscall");
}

// Ignored signals that interrupt a bounded sleep do not end it before its deadline, and once it
// ends, restart_syscall resumes it again, returning at once. That the signals interrupt the sleep
// at all, rather than coming before or after it, is left to chance, so what restart_syscall
// returns is checked against whether the sleep reported the time left.
static void test_ignored_signals_resume_sleep_until_deadline(void) {
    static struct sleeper s;
    start_sleeper(&s, 0, (struct timespec){.tv_sec = 0, .tv_nsec = SLEEP_NS});
    signal_until(SIGCHLD, is_done, &s.result, SIGNAL_WINDOW_MS);
    finish_sleeper(&s);

    expect_slept_through(&s.result, "ignored signal");
    if (s.result.remain.tv_sec == -1) {
        expect_eintr(s.result.restart_ret, s.result.restart_err,
                     "ignored signal, uninterrupted: restart_syscall");
        return;
    }
    if (s.result.remain.tv_sec != 0 || s.result.remain.tv_nsec <= 0 ||
        s.result.remain.tv_nsec >= SLEEP_NS) {
        printf("FAIL: ignored signal: remain %ld.%09ld\n", (long)s.result.remain.tv_sec,
               s.result.remain.tv_nsec);
        exit(1);
    }
    if (s.result.restart_ret != 0) {
        printf("FAIL: ignored signal: restart_syscall ret=%d errno=%d, expected 0\n",
               s.result.restart_ret, s.result.restart_err);
        exit(1);
    }
}

// An absolute sleep that ignored signals interrupt is reissued with its deadline, so it returns 0
// once the deadline passes, without reporting the time left or leaving anything for
// restart_syscall to resume.
static void test_ignored_signals_restart_absolute_sleep(void) {
    static struct sleeper s;
    start_sleeper(&s, 1, (struct timespec){.tv_sec = 0, .tv_nsec = SLEEP_NS});
    signal_until(SIGCHLD, is_done, &s.result, SIGNAL_WINDOW_MS);
    finish_sleeper(&s);

    expect_slept_through(&s.result, "absolute sleep, ignored signal");
    expect_remain_untouched(&s.result, "absolute sleep, ignored signal");
    expect_eintr(s.result.restart_ret, s.result.restart_err,
                 "absolute sleep, ignored signal: restart_syscall");
}

// A handler interrupts an absolute sleep, even with SA_RESTART, which does not report the time
// left. The sleep lasts an hour, so only the handler can end it.
static void test_handler_interrupts_absolute_sleep(void) {
    set_handler(SIGUSR1, handle_signal, SA_RESTART);
    static struct sleeper s;
    start_sleeper(&s, 1, (struct timespec){.tv_sec = 3600, .tv_nsec = 0});
    signal_until(SIGCHLD, is_done, &s.result, SIGNAL_WINDOW_MS);
    if (is_done(&s.result)) {
        printf("FAIL: absolute sleep: an ignored signal ended it: ret=%d errno=%d\n",
               s.result.ret, s.result.err);
        exit(1);
    }
    end_sleep_with_handler(&s.result);
    finish_sleeper(&s);
    set_handler(SIGUSR1, SIG_DFL, 0);

    expect_eintr(s.result.ret, s.result.err, "absolute sleep, handler: clock_nanosleep");
    expect_remain_untouched(&s.result, "absolute sleep, handler");
    expect_eintr(s.result.restart_ret, s.result.restart_err,
                 "absolute sleep, handler: restart_syscall");
}

int main(void) {
    printf("Testing nanosleep restart...\n");
    test_restart_syscall_fails_without_interrupted_sleep();
    test_ignored_signals_never_end_sleep(0);
    test_ignored_signals_never_end_sleep(SA_RESTART);
    test_ignored_signals_resume_sleep_until_deadline();
    test_ignored_signals_restart_absolute_sleep();
    test_handler_interrupts_absolute_sleep();
    printf("All nanosleep restart tests passed.\n");
    return 0;
}
