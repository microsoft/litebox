// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: alarm syscall and SIGALRM delivery

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>

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

// Test that alarm(0) returns 0 when no alarm is pending.
int test_alarm_no_pending(void) {
    unsigned int remaining = alarm(0);
    TEST_ASSERT(remaining == 0, "alarm(0) should return 0 when no alarm is pending");

    printf("alarm_no_pending: PASS\n");
    return 0;
}

// Test that alarm() returns the remaining seconds of a previous alarm.
int test_alarm_returns_remaining(void) {
    alarm(10);
    unsigned int remaining = alarm(0);
    TEST_ASSERT(remaining > 0, "alarm(0) should return remaining seconds");
    TEST_ASSERT(remaining <= 10, "remaining should be <= 10");

    printf("alarm_returns_remaining: PASS (remaining=%u)\n", remaining);
    return 0;
}

// Test that alarm() replaces a previous alarm and returns its remaining time.
int test_alarm_replace(void) {
    alarm(10);
    unsigned int remaining = alarm(5);
    TEST_ASSERT(remaining > 0, "replacing alarm should return remaining seconds");
    TEST_ASSERT(remaining <= 10, "remaining should be <= 10");

    // Cancel the replacement alarm.
    remaining = alarm(0);
    TEST_ASSERT(remaining > 0, "second alarm should have remaining time");
    TEST_ASSERT(remaining <= 5, "remaining should be <= 5");

    printf("alarm_replace: PASS\n");
    return 0;
}

// Test that SIGALRM is actually delivered after the alarm fires.
int test_alarm_fires(void) {
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    alarm_count = 0;
    alarm(1);

    // sleep(2) should be interrupted by SIGALRM after ~1 second.
    sleep(2);

    TEST_ASSERT(alarm_count == 1, "SIGALRM should have been delivered exactly once");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &sa, NULL);

    printf("alarm_fires: PASS\n");
    return 0;
}

// Test that alarm(0) cancels a pending alarm so SIGALRM is not delivered.
int test_alarm_cancel(void) {
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    alarm_count = 0;
    alarm(1);
    alarm(0);  // Cancel it.

    // Sleep briefly; SIGALRM should not fire.
    struct timespec req = { .tv_sec = 2, .tv_nsec = 0 };
    nanosleep(&req, NULL);

    TEST_ASSERT(alarm_count == 0, "SIGALRM should not fire after alarm(0) cancellation");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &sa, NULL);

    printf("alarm_cancel: PASS\n");
    return 0;
}

// Test that SIGALRM is delivered while guest code is spinning in userspace
// (not blocked in a syscall). This exercises the schedule_interrupt mechanism.
int test_alarm_fires_in_userspace(void) {
    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    alarm_count = 0;
    alarm(1);

    // Busy-wait (no syscalls) until SIGALRM arrives.
    // The platform's schedule_interrupt mechanism should interrupt us.
    volatile int i = 0;
    while (alarm_count == 0) {
        i++;
        // Avoid the compiler optimizing this away.
        if (i < 0)
            break;
    }

    TEST_ASSERT(alarm_count == 1, "SIGALRM should have been delivered during userspace spin");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &sa, NULL);

    printf("alarm_fires_in_userspace: PASS (loop iterations=%d)\n", i);
    return 0;
}

// Test: SIGALRM should interrupt poll() blocked on a pipe with no data.
int test_alarm_interrupts_poll(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    struct sigaction sa;
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }
    alarm_count = 0;

    struct pollfd fds[1];
    fds[0].fd = pipefd[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    alarm(1);  // Fire SIGALRM in 1 second

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int ret = poll(fds, 1, 60000);  // 60s timeout — should be interrupted long before

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                      (end.tv_nsec - start.tv_nsec) / 1000000;

    TEST_ASSERT(ret == -1 && errno == EINTR,
                "poll() should return -1/EINTR when interrupted by SIGALRM");
    TEST_ASSERT(alarm_count == 1, "alarm handler should have fired exactly once");
    TEST_ASSERT(elapsed_ms < 5000,
                "poll() should have been interrupted within ~1s, not blocked for 60s");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("alarm_interrupts_poll: PASS (elapsed=%ldms)\n", elapsed_ms);
    return 0;
}

int main(void) {
    printf("Starting alarm tests...\n");

    if (test_alarm_no_pending() != 0) return 1;
    if (test_alarm_returns_remaining() != 0) return 1;
    if (test_alarm_replace() != 0) return 1;
    if (test_alarm_fires() != 0) return 1;
    if (test_alarm_cancel() != 0) return 1;
    if (test_alarm_fires_in_userspace() != 0) return 1;
    if (test_alarm_interrupts_poll() != 0) return 1;
    printf("All alarm tests passed!\n");
    return 0;
}
