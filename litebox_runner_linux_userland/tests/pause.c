// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: pause syscall

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

static volatile sig_atomic_t alarm_count = 0;

static void alarm_handler(int sig) {
    (void)sig;
    alarm_count++;
}

// pause() should return -1 with errno=EINTR after a caught signal
// (delivered here via alarm()), and the handler must run exactly once.
int test_pause_returns_eintr(void) {
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction failed");

    alarm_count = 0;
    alarm(1);

    errno = 0;
    int ret = pause();
    int saved_errno = errno;

    TEST_ASSERT(ret == -1, "pause() must return -1 after a caught signal");
    TEST_ASSERT(saved_errno == EINTR, "pause() must set errno to EINTR");
    TEST_ASSERT(alarm_count == 1, "alarm handler must run exactly once");

    sa.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &sa, NULL);

    printf("pause_returns_eintr: PASS\n");
    return 0;
}

// Same check but via the raw syscall (no libc wrapper munging), since the
// shim intercepts the raw syscall.
int test_pause_raw_syscall(void) {
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction failed");

    alarm_count = 0;
    alarm(1);

    errno = 0;
    long ret = syscall(SYS_pause);
    int saved_errno = errno;

    TEST_ASSERT(ret == -1, "syscall(SYS_pause) must return -1");
    TEST_ASSERT(saved_errno == EINTR, "syscall(SYS_pause) must set errno to EINTR");
    TEST_ASSERT(alarm_count == 1, "alarm handler must run exactly once");

    sa.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &sa, NULL);

    printf("pause_raw_syscall: PASS\n");
    return 0;
}

// pause() is never restarted, even when the catching handler was installed
// with SA_RESTART. See `man 7 signal`: pause is one of the syscalls that
// always returns -1/EINTR on a caught signal regardless of SA_RESTART.
int test_pause_not_restarted_under_sa_restart(void) {
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction failed");

    alarm_count = 0;
    alarm(1);

    errno = 0;
    int ret = pause();
    int saved_errno = errno;

    TEST_ASSERT(ret == -1, "pause() must return -1 even with SA_RESTART");
    TEST_ASSERT(saved_errno == EINTR, "pause() must still return EINTR with SA_RESTART");
    TEST_ASSERT(alarm_count == 1, "alarm handler must run exactly once");

    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

    printf("pause_not_restarted_under_sa_restart: PASS\n");
    return 0;
}

// A signal explicitly set to SIG_IGN is discarded and must not wake pause().
// We verify this by first raising an ignored signal (which would be a no-op),
// then arming alarm() so a caught signal eventually wakes pause(). If
// pause() incorrectly returned for the ignored signal, the elapsed time
// would be far below the alarm interval.
int test_pause_ignores_ignored_signal(void) {
    struct sigaction sa_ign;
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    sa_ign.sa_flags = 0;
    TEST_ASSERT(sigaction(SIGUSR1, &sa_ign, NULL) == 0, "sigaction(SIGUSR1, IGN) failed");

    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction(SIGALRM) failed");

    // Raise the ignored signal so it would already be pending if not discarded.
    TEST_ASSERT(raise(SIGUSR1) == 0, "raise(SIGUSR1) failed");

    alarm_count = 0;
    alarm(1);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    errno = 0;
    int ret = pause();
    int saved_errno = errno;

    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                      (end.tv_nsec - start.tv_nsec) / 1000000;

    TEST_ASSERT(ret == -1, "pause() must return -1");
    TEST_ASSERT(saved_errno == EINTR, "pause() must set errno to EINTR");
    TEST_ASSERT(alarm_count == 1, "alarm handler must run exactly once");
    TEST_ASSERT(elapsed_ms >= 500,
                "pause() must not have returned early on the ignored SIGUSR1");

    sa.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    printf("pause_ignores_ignored_signal: PASS (elapsed=%ldms)\n", elapsed_ms);
    return 0;
}

int main(void) {
    printf("Starting pause tests...\n");

    if (test_pause_returns_eintr() != 0) return 1;
    if (test_pause_raw_syscall() != 0) return 1;
    if (test_pause_not_restarted_under_sa_restart() != 0) return 1;
    if (test_pause_ignores_ignored_signal() != 0) return 1;

    printf("All pause tests passed!\n");
    return 0;
}
