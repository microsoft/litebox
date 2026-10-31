// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#include "helpers.h"

// The kernel's sigset_t, which raw syscalls take, is 8 bytes; glibc's is larger.
#define KERNEL_SIGSET_SIZE 8

static uint64_t bit(int signal) { return 1ULL << (signal - 1); }

static uint64_t pending(void) {
    uint64_t set = ~0ULL;
    TEST_ASSERT(syscall(SYS_rt_sigpending, &set, KERNEL_SIGSET_SIZE) == 0, "rt_sigpending");
    return set;
}

static void expect_pending(uint64_t expected, const char *what) {
    uint64_t set = pending();
    if (set != expected) {
        printf("FAIL: %s: pending %#llx, expected %#llx\n", what, (unsigned long long)set,
               (unsigned long long)expected);
        exit(1);
    }
}

static void block(int signal) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signal);
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0, "pthread_sigmask");
}

static void unblock(int signal) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signal);
    TEST_ASSERT(pthread_sigmask(SIG_UNBLOCK, &set, NULL) == 0, "pthread_sigmask");
}

static atomic_int handled;

static void count_signal(int signal) {
    (void)signal;
    atomic_fetch_add(&handled, 1);
}

static void test_blocked_signals_are_pending(void) {
    expect_pending(0, "nothing sent");
    set_handler(SIGUSR1, count_signal, 0);
    set_handler(SIGUSR2, count_signal, 0);
    block(SIGUSR1);
    block(SIGUSR2);
    TEST_ASSERT(syscall(SYS_tgkill, getpid(), gettid(), SIGUSR1) == 0, "tgkill");
    TEST_ASSERT(kill(getpid(), SIGUSR2) == 0, "kill");
    expect_pending(bit(SIGUSR1) | bit(SIGUSR2), "thread and process signals");
    atomic_store(&handled, 0);
    unblock(SIGUSR1);
    unblock(SIGUSR2);
    TEST_ASSERT(atomic_load(&handled) == 2, "the handlers take the signals");
    expect_pending(0, "signals taken");
    set_handler(SIGUSR1, SIG_DFL, 0);
    set_handler(SIGUSR2, SIG_DFL, 0);
}

// No process is stopped here, so SIGCONT has no continuation work.
static void test_blocked_ignored_signals_are_pending(void) {
    block(SIGCHLD);
    block(SIGURG);
    block(SIGCONT);
    set_handler(SIGURG, SIG_IGN, 0);
    TEST_ASSERT(raise(SIGCHLD) == 0, "raise");
    TEST_ASSERT(kill(getpid(), SIGURG) == 0, "kill");
    TEST_ASSERT(raise(SIGCONT) == 0, "raise");
    expect_pending(bit(SIGCHLD) | bit(SIGURG) | bit(SIGCONT), "ignored signals");
    set_handler(SIGCHLD, SIG_IGN, 0);
    expect_pending(bit(SIGURG) | bit(SIGCONT), "SIGCHLD ignored by its action");
    set_handler(SIGCONT, SIG_DFL, 0);
    expect_pending(bit(SIGURG), "SIGCONT ignored by its default action");
    set_handler(SIGURG, SIG_IGN, 0);
    expect_pending(0, "the process's SIGURG ignored by its action again");
    set_handler(SIGCHLD, SIG_DFL, 0);
    set_handler(SIGURG, SIG_DFL, 0);
    unblock(SIGCHLD);
    unblock(SIGURG);
    unblock(SIGCONT);
}

struct other {
    pthread_t thread;
    atomic_int state;
    uint64_t pending;
    int signal;
    int discard;
};

enum { RAISED = 1, CHECKED };

static void wait_state(const atomic_int *state, int expected, const char *what) {
    struct timespec deadline, now;
    TEST_ASSERT(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0, "clock_gettime");
    deadline.tv_sec += 5;
    while (atomic_load(state) != expected) {
        TEST_ASSERT(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "clock_gettime");
        TEST_ASSERT(now.tv_sec < deadline.tv_sec ||
                        (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec),
                    what);
        sleep_ms(1);
    }
}

static void *other_main(void *arg) {
    struct other *o = arg;
    block(o->signal);
    TEST_ASSERT(raise(o->signal) == 0, "raise");
    o->pending = pending();
    atomic_store(&o->state, RAISED);
    wait_state(&o->state, CHECKED, "main thread did not finish its pending check");
    if (o->discard) {
        expect_pending(0, "another thread's disposition change discards pending signals");
        TEST_ASSERT(raise(o->signal) == 0, "raise while ignored and blocked");
        expect_pending(bit(o->signal), "a newly sent ignored blocked signal stays pending");
        set_handler(o->signal, count_signal, 0);
        expect_pending(bit(o->signal), "installing a handler preserves the newly pending signal");
    }
    unblock(o->signal);
    return NULL;
}

static void test_other_thread_signal_is_not_pending_here(void) {
    set_handler(SIGUSR1, count_signal, 0);
    block(SIGUSR1);
    static struct other o = {.signal = SIGUSR1};
    TEST_ASSERT(pthread_create(&o.thread, NULL, other_main, &o) == 0, "pthread_create");
    wait_state(&o.state, RAISED, "other thread did not queue its signal");
    expect_pending(0, "a signal another thread sent itself");
    atomic_store(&o.state, CHECKED);
    TEST_ASSERT(pthread_join(o.thread, NULL) == 0, "pthread_join");
    if (o.pending != bit(SIGUSR1)) {
        printf("FAIL: other thread: pending %#llx\n", (unsigned long long)o.pending);
        exit(1);
    }
    unblock(SIGUSR1);
    set_handler(SIGUSR1, SIG_DFL, 0);
}

static void test_ignoring_signal_discards_other_thread_pending(int signal,
                                                             void (*action)(int)) {
    set_handler(signal, count_signal, 0);
    block(signal);
    atomic_store(&handled, 0);
    static struct other o;
    o = (struct other){.signal = signal, .discard = 1};
    TEST_ASSERT(pthread_create(&o.thread, NULL, other_main, &o) == 0, "pthread_create");
    wait_state(&o.state, RAISED, "other thread did not queue its signal");
    TEST_ASSERT(o.pending == bit(signal), "other thread queued its signal before sigaction");
    set_handler(signal, action, 0);
    atomic_store(&o.state, CHECKED);
    TEST_ASSERT(pthread_join(o.thread, NULL) == 0, "pthread_join");
    TEST_ASSERT(atomic_load(&handled) == 1, "only the newly queued signal reaches its handler");
    unblock(signal);
    set_handler(signal, SIG_DFL, 0);
}

static void test_sizes(void) {
    block(SIGUSR1);
    set_handler(SIGUSR1, count_signal, 0);
    TEST_ASSERT(raise(SIGUSR1) == 0, "raise");

    uint64_t set = ~0ULL;
    TEST_ASSERT(syscall(SYS_rt_sigpending, &set, 4) == 0, "rt_sigpending with 4 bytes");
    TEST_ASSERT(set == (0xffffffff00000000ULL | bit(SIGUSR1)), "only 4 bytes written");
    set = ~0ULL;
    TEST_ASSERT(syscall(SYS_rt_sigpending, &set, 0) == 0, "rt_sigpending with 0 bytes");
    TEST_ASSERT(set == ~0ULL, "nothing written");
    TEST_ASSERT(syscall(SYS_rt_sigpending, NULL, 0) == 0, "rt_sigpending to NULL with 0 bytes");

    errno = 0;
    TEST_ASSERT(syscall(SYS_rt_sigpending, &set, KERNEL_SIGSET_SIZE + 1) == -1 && errno == EINVAL,
                "rt_sigpending with too large a size");
    errno = 0;
    TEST_ASSERT(syscall(SYS_rt_sigpending, NULL, KERNEL_SIGSET_SIZE) == -1 && errno == EFAULT,
                "rt_sigpending to NULL");

    unblock(SIGUSR1);
    set_handler(SIGUSR1, SIG_DFL, 0);
}

int main(void) {
    printf("Testing rt_sigpending...\n");
    test_blocked_signals_are_pending();
    test_blocked_ignored_signals_are_pending();
    test_other_thread_signal_is_not_pending_here();
    test_ignoring_signal_discards_other_thread_pending(SIGUSR1, SIG_IGN);
    test_ignoring_signal_discards_other_thread_pending(SIGCHLD, SIG_DFL);
    test_ignoring_signal_discards_other_thread_pending(SIGCONT, SIG_DFL);
    test_sizes();
    printf("All rt_sigpending tests passed.\n");
    return 0;
}
