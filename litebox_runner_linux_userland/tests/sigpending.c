// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks rt_sigpending: it reports the signals pending for this thread or its process that this
// thread blocks, including ignored ones, which stay queued while blocked until an action ignores
// them, and writes at most the size it is given, failing with EINVAL for a size larger than the
// kernel's sigset_t.

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

// Blocked signals sent to this thread or to the process are pending until unblocked, when their
// handlers take them.
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

// An ignored signal stays queued while blocked, whether ignored by default, as SIGCONT is when no
// process is stopped, or by its action, until an action that ignores it discards it, for this
// thread or the process.
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
};

enum { RAISED = 1, CHECKED };

static void *other_main(void *arg) {
    struct other *o = arg;
    block(SIGUSR1);
    TEST_ASSERT(raise(SIGUSR1) == 0, "raise");
    o->pending = pending();
    atomic_store(&o->state, RAISED);
    while (atomic_load(&o->state) != CHECKED) {
        sched_yield();
    }
    // Takes the signal, so it does not linger once the thread exits.
    unblock(SIGUSR1);
    return NULL;
}

// A signal another thread sends itself is pending for it alone.
static void test_other_thread_signal_is_not_pending_here(void) {
    set_handler(SIGUSR1, count_signal, 0);
    block(SIGUSR1);
    static struct other o;
    TEST_ASSERT(pthread_create(&o.thread, NULL, other_main, &o) == 0, "pthread_create");
    while (atomic_load(&o.state) != RAISED) {
        sched_yield();
    }
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

// rt_sigpending writes at most the size it is given, failing with EINVAL for a larger size than
// the kernel's sigset_t and with EFAULT for memory it cannot write.
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
    test_sizes();
    printf("All rt_sigpending tests passed.\n");
    return 0;
}
