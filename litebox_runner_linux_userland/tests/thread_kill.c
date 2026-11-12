// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// `tkill`, `tgkill`, and `pthread_kill` direct signals to sibling threads.

#include "helpers.h"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/resource.h>

static atomic_int handler_tid;
static atomic_int handler_sender;
static atomic_int handler_code;
static atomic_int target_tid;
static atomic_int stage;

static void on_signal(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    atomic_store(&handler_sender, info->si_pid);
    atomic_store(&handler_code, info->si_code);
    atomic_store(&handler_tid, gettid());
}

static void wait_for_stage(int expected) {
    wait_for_value(&stage, expected, "a thread never reached its stage");
}

// Waits in `sigsuspend` with SIGUSR1 pending until it runs the handler.
static void *suspend_target(void *arg) {
    (void)arg;
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &usr1, NULL) == 0, "block SIGUSR1 failed");
    atomic_store(&target_tid, gettid());
    atomic_store(&stage, 1);
    // SIGUSR1 stays pending for this thread while blocked.
    wait_for_stage(2);
    TEST_ASSERT(is_pending(SIGUSR1), "SIGUSR1 should be pending for its target");
    sigset_t none;
    sigemptyset(&none);
    expect_errno(sigsuspend(&none), EINTR, "sigsuspend should be interrupted");
    TEST_ASSERT(atomic_load(&handler_tid) == gettid(), "the handler ran on another thread");
    return NULL;
}

// Spins in guest code, without syscalls, until the handler runs on this thread.
static void *spin_target(void *arg) {
    (void)arg;
    // Threads start with their creator's mask, which blocks SIGUSR2.
    sigset_t usr2;
    sigemptyset(&usr2);
    sigaddset(&usr2, SIGUSR2);
    TEST_ASSERT(pthread_sigmask(SIG_UNBLOCK, &usr2, NULL) == 0, "unblock SIGUSR2 failed");
    int tid = gettid();
    atomic_store(&target_tid, tid);
    // No syscall follows, so the signal must interrupt guest code. The sender times the wait.
    atomic_store(&stage, 1);
    while (atomic_load(&handler_tid) != tid) {
        SPIN_HINT();
    }
    return NULL;
}

// Takes the two queued instances of SIGRTMIN that were sent to it.
static void *queue_target(void *arg) {
    (void)arg;
    sigset_t rt;
    sigemptyset(&rt);
    sigaddset(&rt, SIGRTMIN);
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &rt, NULL) == 0, "block SIGRTMIN failed");
    atomic_store(&target_tid, gettid());
    atomic_store(&stage, 1);
    wait_for_stage(2);
    TEST_ASSERT(is_pending(SIGRTMIN), "SIGRTMIN should be pending for its target");
    struct timespec zero = {0, 0};
    for (int i = 0; i < 2; i++) {
        siginfo_t info;
        TEST_ASSERT(sigtimedwait(&rt, &info, &zero) == SIGRTMIN, "queued SIGRTMIN missing");
        TEST_ASSERT(info.si_pid == getpid(), "SIGRTMIN should name this process as sender");
    }
    expect_errno(sigtimedwait(&rt, NULL, &zero), EAGAIN, "only two SIGRTMIN should be queued");
    return NULL;
}

// Exits with SIGUSR1 pending for it alone.
static void *exit_target(void *arg) {
    (void)arg;
    atomic_store(&target_tid, gettid());
    atomic_store(&stage, 1);
    wait_for_stage(2);
    TEST_ASSERT(is_pending(SIGUSR1), "SIGUSR1 should be pending for its target");
    return NULL;
}

// Waits in `epoll_wait` until it times out, which ignored signals must not interrupt.
static void *ignore_target(void *arg) {
    (void)arg;
    int epoll = epoll_create1(0);
    TEST_ASSERT(epoll >= 0, "epoll_create1 failed");
    atomic_store(&target_tid, gettid());
    atomic_store(&stage, 1);
    struct epoll_event event;
    int result = epoll_wait(epoll, &event, 1, 200);
    TEST_ASSERT(result == 0, "ignored signals should not interrupt epoll_wait");
    TEST_ASSERT(close(epoll) == 0, "close failed");
    atomic_store(&stage, 2);
    // Still a target until the sender stops.
    wait_for_stage(3);
    return NULL;
}

// Blocks SIGPIPE, which the process ignores, and waits for it in `rt_sigtimedwait`.
static void *ignored_wait_target(void *arg) {
    (void)arg;
    sigset_t pipe_set;
    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &pipe_set, NULL) == 0, "block SIGPIPE failed");
    atomic_store(&target_tid, gettid());
    atomic_store(&stage, 1);
    struct timespec timeout = {10, 0};
    siginfo_t info;
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &pipe_set, &info, &timeout, _NSIG / 8) == SIGPIPE,
                "a blocked SIGPIPE should be taken though the process ignores it");
    TEST_ASSERT(info.si_code == SI_TKILL && info.si_pid == getpid(),
                "the blocked SIGPIPE should keep its sender");
    return NULL;
}

static pthread_t main_thread;

// Signals the main thread after it ends, which, like a group leader on Linux, still takes signals
// until the process ends, dropping them. Then ends the test.
static void *signal_ended_main_and_exit(void *arg) {
    (void)arg;
    TEST_ASSERT(pthread_join(main_thread, NULL) == 0, "joining the main thread failed");
    pid_t pid = getpid();
    TEST_ASSERT(syscall(SYS_tkill, pid, 0) == 0, "tkill probe of the ended main thread failed");
    TEST_ASSERT(syscall(SYS_tgkill, pid, pid, 0) == 0,
                "tgkill probe of the ended main thread failed");
    TEST_ASSERT(syscall(SYS_tkill, pid, SIGUSR1) == 0, "tkill to the ended main thread failed");
    TEST_ASSERT(syscall(SYS_tgkill, pid, pid, SIGUSR1) == 0,
                "tgkill to the ended main thread failed");
    expect_errno(syscall(SYS_tgkill, pid, pid, 1000), EINVAL,
                 "tgkill to the ended main thread with an invalid signal should fail with EINVAL");
    TEST_ASSERT(!is_pending(SIGUSR1), "signals to the ended main thread should be dropped");
    printf("thread_kill: all tests passed\n");
    fflush(stdout);
    exit(0);
}

// Returns the signals queued for this process's user, from the `SigQ` line of
// `/proc/self/status`, or zero where it is not reported.
static rlim_t user_queued_signals(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL) {
        return 0;
    }
    char line[256];
    unsigned long used = 0;
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "SigQ: %lu/", &used) == 1) {
            break;
        }
    }
    TEST_ASSERT(fclose(status) == 0, "fclose failed");
    return used;
}

static pthread_t start_target(void *(*target)(void *)) {
    atomic_store(&stage, 0);
    atomic_store(&handler_tid, 0);
    atomic_store(&handler_sender, 0);
    atomic_store(&handler_code, 0);
    pthread_t thread;
    TEST_ASSERT(pthread_create(&thread, NULL, target, NULL) == 0, "pthread_create failed");
    wait_for_stage(1);
    return thread;
}

int main(void) {
    // Ends the test should a signal never arrive.
    alarm(30);
    struct sigaction action = {.sa_sigaction = on_signal, .sa_flags = SA_SIGINFO};
    TEST_ASSERT(sigaction(SIGUSR1, &action, NULL) == 0, "sigaction SIGUSR1 failed");
    TEST_ASSERT(sigaction(SIGUSR2, &action, NULL) == 0, "sigaction SIGUSR2 failed");
    // This thread must not take signals meant for the others.
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    sigaddset(&blocked, SIGUSR2);
    sigaddset(&blocked, SIGRTMIN);
    sigaddset(&blocked, SIGRTMIN + 1);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0, "sigprocmask failed");

    // `pthread_kill` queues a blocked signal that the sibling handles in `sigsuspend`.
    pthread_t thread = start_target(suspend_target);
    TEST_ASSERT(pthread_kill(thread, SIGUSR1) == 0, "pthread_kill failed");
    TEST_ASSERT(!is_pending(SIGUSR1), "SIGUSR1 should not be pending for the sender");
    atomic_store(&stage, 2);
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join failed");
    TEST_ASSERT(atomic_load(&handler_sender) == getpid(), "SIGUSR1 sender should be this process");
    // Unlike glibc's `sigwaitinfo`, a handler sees the code the kernel reports.
    TEST_ASSERT(atomic_load(&handler_code) == SI_TKILL, "SIGUSR1 should have code SI_TKILL");

    // `tkill` interrupts a sibling running guest code.
    thread = start_target(spin_target);
    TEST_ASSERT(syscall(SYS_tkill, atomic_load(&target_tid), SIGUSR2) == 0, "tkill failed");
    wait_for_value(&handler_tid, atomic_load(&target_tid), "spinning thread never took SIGUSR2");
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join failed");

    // `tgkill` queues real-time signals for the sibling alone.
    thread = start_target(queue_target);
    int tid = atomic_load(&target_tid);
    for (int i = 0; i < 2; i++) {
        TEST_ASSERT(syscall(SYS_tgkill, getpid(), tid, SIGRTMIN) == 0, "tgkill failed");
    }
    TEST_ASSERT(!is_pending(SIGRTMIN), "SIGRTMIN should not be pending for the sender");

    // Signal zero only checks the target, and the thread must belong to the given process.
    TEST_ASSERT(syscall(SYS_tkill, tid, 0) == 0, "tkill probe failed");
    TEST_ASSERT(syscall(SYS_tgkill, getpid(), tid, 0) == 0, "tgkill probe failed");
    expect_errno(syscall(SYS_tgkill, tid, tid, 0), ESRCH,
                 "tgkill with another thread group ID should fail with ESRCH");
    expect_errno(syscall(SYS_tgkill, tid, gettid(), 0), ESRCH,
                 "tgkill to self with another thread group ID should fail with ESRCH");
    expect_errno(syscall(SYS_tkill, tid, 1000), EINVAL,
                 "tkill with an invalid signal should fail with EINVAL");
    // Like Linux, a missing target is reported before an invalid signal.
    expect_errno(syscall(SYS_tkill, 0x3fffffff, 1000), ESRCH,
                 "tkill to an unused ID with an invalid signal should fail with ESRCH");
    expect_errno(syscall(SYS_tgkill, getpid(), 0x3fffffff, 1000), ESRCH,
                 "tgkill to an unused ID with an invalid signal should fail with ESRCH");
    expect_errno(syscall(SYS_tgkill, tid, tid, 1000), ESRCH,
                 "tgkill with another thread group ID and an invalid signal should be ESRCH");
    atomic_store(&stage, 2);
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join failed");

    // A thread that exits drops the signals pending for it alone.
    thread = start_target(exit_target);
    TEST_ASSERT(pthread_kill(thread, SIGUSR1) == 0, "pthread_kill failed");
    atomic_store(&stage, 2);
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join failed");
    TEST_ASSERT(!is_pending(SIGUSR1), "the exited thread's SIGUSR1 should not be pending");
    TEST_ASSERT(atomic_load(&handler_tid) == 0, "the exited thread's SIGUSR1 should not run");

    // Like Linux, which drops a signal its target ignores without blocking when it is sent, ignored
    // signals do not interrupt a sibling's wait. SIGURG is ignored by default.
    TEST_ASSERT(signal(SIGPIPE, SIG_IGN) != SIG_ERR, "ignoring SIGPIPE failed");
    thread = start_target(ignore_target);
    tid = atomic_load(&target_tid);
    while (atomic_load(&stage) != 2) {
        TEST_ASSERT(syscall(SYS_tgkill, getpid(), tid, SIGPIPE) == 0, "tgkill SIGPIPE failed");
        TEST_ASSERT(syscall(SYS_tkill, tid, SIGURG) == 0, "tkill SIGURG failed");
        sched_yield();
    }
    atomic_store(&stage, 3);
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join failed");

    // Like Linux, a blocked signal is never ignored, even while `rt_sigtimedwait` unblocks it to
    // wait for it. The delay lets the signal likely arrive during the wait; either way it is taken.
    thread = start_target(ignored_wait_target);
    sleep_ms(100);
    TEST_ASSERT(syscall(SYS_tgkill, getpid(), atomic_load(&target_tid), SIGPIPE) == 0,
                "tgkill SIGPIPE failed");
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join failed");

    // Real-time signals queue up to `RLIMIT_SIGPENDING`, past which they fail with EAGAIN. Linux
    // counts the signals pending for every process of the user, so the limit leaves room past
    // those already queued.
    struct rlimit limit;
    TEST_ASSERT(getrlimit(RLIMIT_SIGPENDING, &limit) == 0, "getrlimit failed");
    rlim_t used = user_queued_signals();
    TEST_ASSERT(limit.rlim_max >= 16 && used <= limit.rlim_max - 16,
                "RLIMIT_SIGPENDING leaves no room for 16 more signals");
    struct rlimit few = {.rlim_cur = used + 16, .rlim_max = limit.rlim_max};
    TEST_ASSERT(setrlimit(RLIMIT_SIGPENDING, &few) == 0, "setrlimit failed");
    int queued = 0;
    errno = 0;
    while (syscall(SYS_tgkill, getpid(), gettid(), SIGRTMIN) == 0) {
        queued++;
        TEST_ASSERT((rlim_t)queued <= few.rlim_cur, "tgkill should fail past RLIMIT_SIGPENDING");
    }
    if (queued == 0) {
        // Other processes of the user may have queued signals since `used` was read.
        fprintf(stderr, "queued none with %lu of %lu already queued for this user\n",
                (unsigned long)user_queued_signals(), (unsigned long)few.rlim_cur);
    }
    TEST_ASSERT(errno == EAGAIN, "tgkill past RLIMIT_SIGPENDING should fail with EAGAIN");
    TEST_ASSERT(queued > 0, "tgkill should queue at least one real-time signal");
    TEST_ASSERT(setrlimit(RLIMIT_SIGPENDING, &limit) == 0, "setrlimit restore failed");
    sigset_t rt;
    sigemptyset(&rt);
    sigaddset(&rt, SIGRTMIN);
    siginfo_t info;
    struct timespec zero = {0, 0};
    for (int i = 0; i < queued; i++) {
        TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &rt, &info, &zero, _NSIG / 8) == SIGRTMIN,
                    "a queued SIGRTMIN is missing");
    }
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &rt, &info, &zero, _NSIG / 8) == -1,
                "SIGRTMIN past RLIMIT_SIGPENDING should not be queued");

    // With no room to queue, a standard signal and a real-time one sent by `kill` are still made
    // pending, once, but without their sender.
    struct rlimit none = {.rlim_cur = 0, .rlim_max = limit.rlim_max};
    TEST_ASSERT(setrlimit(RLIMIT_SIGPENDING, &none) == 0, "setrlimit failed");
    TEST_ASSERT(syscall(SYS_tkill, gettid(), SIGUSR1) == 0, "tkill failed");
    for (int i = 0; i < 2; i++) {
        TEST_ASSERT(kill(getpid(), SIGRTMIN + 1) == 0, "kill failed");
    }
    TEST_ASSERT(setrlimit(RLIMIT_SIGPENDING, &limit) == 0, "setrlimit restore failed");
    sigset_t lost;
    sigemptyset(&lost);
    sigaddset(&lost, SIGUSR1);
    sigaddset(&lost, SIGRTMIN + 1);
    sigset_t seen;
    sigemptyset(&seen);
    // Unlike glibc's `sigtimedwait`, the syscall reports the code unchanged.
    for (int i = 0; i < 2; i++) {
        long taken = syscall(SYS_rt_sigtimedwait, &lost, &info, &zero, _NSIG / 8);
        TEST_ASSERT(taken == SIGUSR1 || taken == SIGRTMIN + 1, "a signal with no room is missing");
        TEST_ASSERT(!sigismember(&seen, taken), "a signal with no room was taken twice");
        sigaddset(&seen, taken);
        TEST_ASSERT(info.si_code == SI_USER && info.si_pid == 0,
                    "a signal with no room should lose its sender");
    }
    TEST_ASSERT(sigismember(&seen, SIGUSR1) && sigismember(&seen, SIGRTMIN + 1),
                "both signals with no room should be pending");
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &lost, &info, &zero, _NSIG / 8) == -1,
                "each signal with no room should be pending once");

    // Nonpositive IDs are invalid.
    expect_errno(syscall(SYS_tkill, 0, 0), EINVAL, "tkill(0) should be EINVAL");
    expect_errno(syscall(SYS_tgkill, 0, gettid(), 0), EINVAL,
                 "tgkill with thread group ID 0 should be EINVAL");

    main_thread = pthread_self();
    TEST_ASSERT(pthread_create(&thread, NULL, signal_ended_main_and_exit, NULL) == 0,
                "pthread_create failed");
    pthread_exit(NULL);
}
