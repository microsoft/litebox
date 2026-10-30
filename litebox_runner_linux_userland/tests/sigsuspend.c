// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks rt_sigsuspend: it waits with its mask until a signal runs a handler, with the handler
// running under that mask, then fails with EINTR and restores the mask from before the call. An
// ignored signal the mask unblocks is discarded without ending the wait, and a signal the mask
// blocks stays pending. A mask of the wrong size fails with EINVAL, and one it cannot read with
// EFAULT, leaving the mask alone.

#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#include "helpers.h"

// The kernel's sigset_t, which raw syscalls take, is 8 bytes; glibc's is larger.
#define KERNEL_SIGSET_SIZE 8
// How long the helper thread waits before signaling, so the call is all but certainly waiting by
// then.
#define SIGNAL_DELAY_MS 100
// Bounds waits for an outcome that is certain, so a broken implementation fails rather than
// hangs.
#define LIVENESS_MS (30L * 1000)

static uint64_t bit(int signal) { return 1ULL << (signal - 1); }

static uint64_t mask(void) {
    uint64_t set = 0;
    TEST_ASSERT(syscall(SYS_rt_sigprocmask, SIG_BLOCK, NULL, &set, KERNEL_SIGSET_SIZE) == 0,
                "rt_sigprocmask");
    return set;
}

static void set_mask(uint64_t set) {
    TEST_ASSERT(syscall(SYS_rt_sigprocmask, SIG_SETMASK, &set, NULL, KERNEL_SIGSET_SIZE) == 0,
                "rt_sigprocmask");
}

static uint64_t pending(void) {
    uint64_t set = 0;
    TEST_ASSERT(syscall(SYS_rt_sigpending, &set, KERNEL_SIGSET_SIZE) == 0, "rt_sigpending");
    return set;
}

static long sigsuspend_with(uint64_t set) {
    errno = 0;
    return syscall(SYS_rt_sigsuspend, &set, KERNEL_SIGSET_SIZE);
}

static void expect_eintr(long ret, const char *what) {
    if (ret != -1 || errno != EINTR) {
        printf("FAIL: %s: ret=%ld errno=%d, expected EINTR\n", what, ret, errno);
        exit(1);
    }
}

static void expect_set(uint64_t set, uint64_t expected, const char *what) {
    if (set != expected) {
        printf("FAIL: %s: %#llx, expected %#llx\n", what, (unsigned long long)set,
               (unsigned long long)expected);
        exit(1);
    }
}

static atomic_int handled_signal;
static atomic_int handler_failed;
static uint64_t mask_in_handler;

static void record_signal(int signal) {
    if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, NULL, &mask_in_handler, KERNEL_SIGSET_SIZE) != 0) {
        atomic_store(&handler_failed, 1);
    }
    atomic_store(&handled_signal, signal);
}

static void reset_handled(void) {
    atomic_store(&handled_signal, 0);
    atomic_store(&handler_failed, 0);
}

static int handled(void) {
    TEST_ASSERT(!atomic_load(&handler_failed), "rt_sigprocmask in the handler");
    return atomic_load(&handled_signal);
}

// A pending signal the mask unblocks runs its handler under the mask, besides its own signal, then
// the call fails with EINTR and restores the mask from before it. A pending signal the mask blocks
// stays pending.
static void test_handler_runs_under_call_mask(void) {
    set_handler(SIGUSR1, record_signal, 0);
    set_handler(SIGUSR2, record_signal, 0);
    reset_handled();
    uint64_t old = mask();
    uint64_t before = old | bit(SIGUSR1) | bit(SIGUSR2) | bit(SIGURG);
    set_mask(before);
    TEST_ASSERT(raise(SIGUSR1) == 0, "raise");
    TEST_ASSERT(raise(SIGUSR2) == 0, "raise");

    expect_eintr(sigsuspend_with(bit(SIGUSR2)), "rt_sigsuspend");
    TEST_ASSERT(handled() == SIGUSR1, "SIGUSR1's handler runs");
    expect_set(mask_in_handler, bit(SIGUSR1) | bit(SIGUSR2), "the mask in the handler");
    expect_set(mask(), before, "the mask after the call");
    expect_set(pending(), bit(SIGUSR2), "pending after the call");

    reset_handled();
    set_mask(old);
    TEST_ASSERT(handled() == SIGUSR2, "SIGUSR2's handler runs once unblocked");
    set_handler(SIGUSR1, SIG_DFL, 0);
    set_handler(SIGUSR2, SIG_DFL, 0);
}

struct signaler {
    atomic_int done;
};

static int is_done(void *arg) {
    struct signaler *s = arg;
    return atomic_load(&s->done);
}

static void *signaler_main(void *arg) {
    sleep_ms(SIGNAL_DELAY_MS);
    if (!signal_until(SIGUSR2, is_done, arg, LIVENESS_MS)) {
        printf("FAIL: rt_sigsuspend did not end\n");
        exit(1);
    }
    return NULL;
}

// An ignored signal the mask unblocks is discarded without ending the wait, which a handled
// signal from another thread then ends. That thread inherits a mask blocking the signals, so only
// the waiting thread takes them.
static void test_ignored_signal_does_not_end_wait(void) {
    set_handler(SIGUSR2, record_signal, 0);
    reset_handled();
    uint64_t old = mask();
    set_mask(old | bit(SIGCHLD) | bit(SIGUSR2));
    TEST_ASSERT(raise(SIGCHLD) == 0, "raise");

    static struct signaler s;
    atomic_store(&s.done, 0);
    pthread_t thread;
    TEST_ASSERT(pthread_create(&thread, NULL, signaler_main, &s) == 0, "pthread_create");
    expect_eintr(sigsuspend_with(0), "rt_sigsuspend with an ignored signal");
    int signal = handled();
    atomic_store(&s.done, 1);
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join");
    if (signal != SIGUSR2) {
        printf("FAIL: rt_sigsuspend ended with signal %d handled, expected %d\n", signal,
               SIGUSR2);
        exit(1);
    }
    expect_set(pending() & bit(SIGCHLD), 0, "SIGCHLD pending after the call");

    // Takes any SIGUSR2 sent since.
    set_mask(old);
    set_handler(SIGUSR2, SIG_DFL, 0);
}

// A mask of the wrong size or that cannot be read fails the call, leaving the mask alone.
static void test_bad_mask(void) {
    uint64_t old = mask();
    uint64_t set = 0;
    for (size_t size = 0; size <= 2 * KERNEL_SIGSET_SIZE; size += 4) {
        if (size == KERNEL_SIGSET_SIZE) {
            continue;
        }
        errno = 0;
        if (syscall(SYS_rt_sigsuspend, &set, size) != -1 || errno != EINVAL) {
            printf("FAIL: rt_sigsuspend with size %zu: errno=%d, expected EINVAL\n", size, errno);
            exit(1);
        }
    }
    errno = 0;
    TEST_ASSERT(syscall(SYS_rt_sigsuspend, NULL, KERNEL_SIGSET_SIZE) == -1 && errno == EFAULT,
                "rt_sigsuspend with a NULL mask");
    expect_set(mask(), old, "the mask after failing");
}

int main(void) {
    printf("Testing rt_sigsuspend...\n");
    test_handler_runs_under_call_mask();
    test_ignored_signal_does_not_end_wait();
    test_bad_mask();
    printf("All rt_sigsuspend tests passed.\n");
    return 0;
}
