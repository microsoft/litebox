// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/select.h>

#include "helpers.h"

#define HOUR 3600
// How long ignored signals are sent at a wait that must survive them.
#define SIGNAL_WINDOW_MS 100
// Bounds waits for an outcome that is certain, so a broken implementation fails rather than
// hangs.
#define LIVENESS_MS (30L * 1000)
#define LIVENESS_TIMESPEC ((struct timespec){.tv_sec = LIVENESS_MS / 1000, .tv_nsec = 0})
// The kernel's sigset_t, which raw syscalls take, is 8 bytes; glibc's is larger.
#define KERNEL_SIGSET_SIZE 8
// Fills the revents of poll's fd until poll writes them.
#define REVENTS_UNWRITTEN 0x7fff

enum call {
    FUTEX_RELATIVE,
    FUTEX_ABSOLUTE,
    FUTEX_UNTIMED,
    POLL,
    PPOLL,
    SELECT,
    PSELECT6,
};

static const char *call_name(enum call call) {
    static const char *const names[] = {"futex (relative timeout)", "futex (absolute timeout)",
                                        "futex (no timeout)",       "poll",
                                        "ppoll",                    "select",
                                        "pselect6"};
    return names[call];
}

struct waiter {
    enum call call;
    int poll_timeout_ms;
    pthread_t thread;
    sigset_t old_mask;
    atomic_int ready;
    atomic_int done;
    long ret;
    int err;
    // What restart_syscall returns after the call, and is expected to return.
    long restart_ret;
    int restart_err;
    long expected_restart_ret;
    uint32_t word;
    struct pollfd fds[1];
    // The relative timeout of futex, ppoll, and pselect6, which the last two write back.
    struct timespec ts;
    // Where the call takes `ts` from, which a test may point elsewhere.
    struct timespec *ts_ptr;
    // The timeout select writes back.
    struct timeval tv;
    // Never written, so its read end is ready only once a test makes it so.
    int idle[2];
    // The signal mask ppoll and pselect6 set, if `use_mask`, and the waiter's mask after the
    // call.
    int use_mask;
    sigset_t mask;
    sigset_t mask_after;
};

static void test_signal_set(sigset_t *set) {
    sigemptyset(set);
    sigaddset(set, SIGCHLD);
    sigaddset(set, SIGUSR1);
    sigaddset(set, SIGUSR2);
}

static long do_call(struct waiter *w) {
    int fd = w->idle[0];
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    switch (w->call) {
    case FUTEX_RELATIVE:
        return syscall(SYS_futex, &w->word, FUTEX_WAIT_PRIVATE, 0, w->ts_ptr, NULL, 0);
    case FUTEX_ABSOLUTE: {
        struct timespec deadline;
        TEST_ASSERT(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0, "clock_gettime");
        deadline.tv_sec += HOUR;
        return syscall(SYS_futex, &w->word, FUTEX_WAIT_BITSET_PRIVATE, 0, &deadline, NULL,
                       FUTEX_BITSET_MATCH_ANY);
    }
    case FUTEX_UNTIMED:
        return syscall(SYS_futex, &w->word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    case POLL:
#ifdef SYS_poll
        return syscall(SYS_poll, w->fds, 1, w->poll_timeout_ms);
#else
        break;
#endif
    case PPOLL:
        return syscall(SYS_ppoll, w->fds, 1, w->ts_ptr, w->use_mask ? &w->mask : NULL,
                       KERNEL_SIGSET_SIZE);
    case SELECT:
#ifdef SYS_select
        return syscall(SYS_select, fd + 1, &readfds, NULL, NULL, &w->tv);
#else
        break;
#endif
    case PSELECT6: {
        struct {
            const sigset_t *mask;
            size_t size;
        } mask_arg = {&w->mask, KERNEL_SIGSET_SIZE};
        return syscall(SYS_pselect6, fd + 1, &readfds, NULL, NULL, w->ts_ptr,
                       w->use_mask ? &mask_arg : NULL);
    }
    }
    die("call not supported on this architecture");
    return -1;
}

static void *waiter_main(void *arg) {
    struct waiter *w = arg;
    if (w->use_mask) {
        // Blocked outside the call only, so a handler shows which mask it was delivered under.
        sigset_t urg;
        sigemptyset(&urg);
        sigaddset(&urg, SIGURG);
        TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &urg, NULL) == 0, "pthread_sigmask");
    }
    atomic_store(&w->ready, 1);
    errno = 0;
    w->ret = do_call(w);
    w->err = errno;
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, NULL, &w->mask_after) == 0, "pthread_sigmask");
    // Signals still on their way must not interrupt what follows.
    sigset_t set;
    test_signal_set(&set);
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0, "pthread_sigmask");
    errno = 0;
    w->restart_ret = syscall(SYS_restart_syscall);
    w->restart_err = errno;
    atomic_store(&w->done, 1);
    return NULL;
}

// Prepares `call`, with a timeout of an hour if it has one.
static void init_waiter(struct waiter *w, enum call call) {
    memset(w, 0, sizeof(*w));
    w->call = call;
    w->poll_timeout_ms = -1;
    w->expected_restart_ret = -1;
    w->ts = (struct timespec){.tv_sec = HOUR, .tv_nsec = 0};
    w->ts_ptr = &w->ts;
    w->tv = (struct timeval){.tv_sec = HOUR, .tv_usec = 0};
    TEST_ASSERT(pipe(w->idle) == 0, "pipe");
    w->fds[0] = (struct pollfd){.fd = w->idle[0], .events = POLLIN};
}

// Starts a waiter making the prepared call, then blocks the test's signals in the main thread,
// so the waiter takes them, and waits until it is about to call.
static void launch_waiter(struct waiter *w) {
    TEST_ASSERT(pthread_create(&w->thread, NULL, waiter_main, w) == 0, "pthread_create");
    // Block the signals only after creating the waiter, which would otherwise inherit the mask.
    sigset_t set;
    test_signal_set(&set);
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &set, &w->old_mask) == 0, "pthread_sigmask");
    while (!atomic_load(&w->ready)) {
        sched_yield();
    }
}

static void start_waiter(struct waiter *w, enum call call) {
    init_waiter(w, call);
    launch_waiter(w);
}

static int is_done(void *arg) {
    struct waiter *w = arg;
    return atomic_load(&w->done);
}

// Sends ignored SIGCHLDs, which must not end the wait.
static void send_ignored_signals(struct waiter *w) {
    if (signal_until(SIGCHLD, is_done, w, SIGNAL_WINDOW_MS)) {
        printf("FAIL: %s: an ignored signal ended the wait: ret=%ld errno=%d\n",
               call_name(w->call), w->ret, w->err);
        exit(1);
    }
}

static void wait_done(struct waiter *w, int signal) {
    if (!signal_until(signal, is_done, w, LIVENESS_MS)) {
        printf("FAIL: %s: the wait did not end\n", call_name(w->call));
        exit(1);
    }
}

// Fails unless the waiter is still waiting.
static void expect_waiting(struct waiter *w, const char *what) {
    if (is_done(w)) {
        printf("FAIL: %s: %s: ret=%ld errno=%d\n", call_name(w->call), what, w->ret, w->err);
        exit(1);
    }
}

// Joins the waiter once it is done, then takes any signals still pending, so a handler must still
// be installed for them.
static void finish_waiter(struct waiter *w) {
    TEST_ASSERT(pthread_join(w->thread, NULL) == 0, "pthread_join");
    TEST_ASSERT(pthread_sigmask(SIG_SETMASK, &w->old_mask, NULL) == 0, "pthread_sigmask");
    close(w->idle[0]);
    close(w->idle[1]);
}

// Checks what the call and the restart_syscall after it returned.
static void expect_result(const struct waiter *w, long ret, int err) {
    if (w->ret != ret || (ret == -1 && w->err != err)) {
        printf("FAIL: %s: ret=%ld errno=%d, expected %ld errno=%d\n", call_name(w->call), w->ret,
               w->err, ret, ret == -1 ? err : 0);
        exit(1);
    }
    long restart = w->expected_restart_ret;
    if (w->restart_ret != restart || (restart == -1 && w->restart_err != EINTR)) {
        printf("FAIL: %s: restart_syscall then: ret=%ld errno=%d, expected %ld errno=%d\n",
               call_name(w->call), w->restart_ret, w->restart_err, restart,
               restart == -1 ? EINTR : 0);
        exit(1);
    }
}

static long futex_wake(uint32_t *word) {
    return syscall(SYS_futex, word, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

// Wakes the waiter once it waits, failing if it ends the wait otherwise.
static void wake_waiter(struct waiter *w) {
    for (long ms = 0; ms < LIVENESS_MS; ms++) {
        if (futex_wake(&w->word) == 1) {
            return;
        }
        expect_waiting(w, "the wait ended without a wake");
        sleep_ms(1);
    }
    printf("FAIL: %s: no waiter to wake\n", call_name(w->call));
    exit(1);
}

// A futex wait goes on through ignored signals until woken.
static void test_futex_wait_survives_ignored_signals(enum call call) {
    static struct waiter w;
    start_waiter(&w, call);
    send_ignored_signals(&w);
    wake_waiter(&w);
    wait_done(&w, SIGCHLD);
    finish_waiter(&w);
    expect_result(&w, 0, 0);
}

// A resumed futex wait checks its word again, so once the word changes, an ignored signal ends
// the wait with EAGAIN. Signals first make the waiter all but certainly wait by then.
static void test_resumed_futex_wait_checks_word(enum call call) {
    static struct waiter w;
    start_waiter(&w, call);
    send_ignored_signals(&w);
    __atomic_store_n(&w.word, 1, __ATOMIC_RELEASE);
    wait_done(&w, SIGCHLD);
    finish_waiter(&w);
    expect_result(&w, -1, EAGAIN);
}

// With SA_RESTART, a handler interrupts a futex wait with a timeout, but restarts one without.
static void test_futex_wait_with_restarting_handler(enum call call) {
    set_handler(SIGUSR1, handle_signal, SA_RESTART);
    static struct waiter w;
    start_waiter(&w, call);
    if (call == FUTEX_UNTIMED) {
        if (signal_until(SIGUSR1, is_done, &w, SIGNAL_WINDOW_MS)) {
            printf("FAIL: %s: a handler with SA_RESTART ended the wait: ret=%ld errno=%d\n",
                   call_name(call), w.ret, w.err);
            exit(1);
        }
        wake_waiter(&w);
    }
    wait_done(&w, SIGUSR1);
    finish_waiter(&w);
    set_handler(SIGUSR1, SIG_DFL, 0);
    expect_result(&w, call == FUTEX_UNTIMED ? 0 : -1, EINTR);
}

#ifdef SYS_poll
static int revents_written_or_done(void *arg) {
    struct waiter *w = arg;
    return __atomic_load_n(&w->fds[0].revents, __ATOMIC_ACQUIRE) != REVENTS_UNWRITTEN ||
           is_done(w);
}

// A resumed poll reads its fds again, so once they include a ready one, an ignored signal ends
// the poll with it ready. The revents poll writes when interrupted show it is resumed by then.
// A later restart_syscall polls the fds again.
static void test_resumed_poll_reads_fds(int timeout_ms) {
    int ready[2];
    TEST_ASSERT(pipe(ready) == 0, "pipe");
    TEST_ASSERT(write(ready[1], "x", 1) == 1, "write");
    static struct waiter w;
    init_waiter(&w, POLL);
    w.poll_timeout_ms = timeout_ms;
    w.fds[0].revents = REVENTS_UNWRITTEN;
    w.expected_restart_ret = 1;
    launch_waiter(&w);
    if (!signal_until(SIGCHLD, revents_written_or_done, &w, LIVENESS_MS)) {
        printf("FAIL: poll: no interruption\n");
        exit(1);
    }
    expect_waiting(&w, "an ignored signal ended the wait");
    __atomic_store_n(&w.fds[0].fd, ready[0], __ATOMIC_RELEASE);
    wait_done(&w, SIGCHLD);
    finish_waiter(&w);
    close(ready[0]);
    close(ready[1]);
    expect_result(&w, 1, 0);
    TEST_ASSERT(w.fds[0].revents == POLLIN, "the ready fd is polled");
}
#endif

static long time_left_sec(const struct waiter *w) {
    return w->call == SELECT ? (long)w->tv.tv_sec : (long)w->ts.tv_sec;
}

static int timeout_written(void *arg) {
    struct waiter *w = arg;
    if (w->call == SELECT) {
        return __atomic_load_n(&w->tv.tv_sec, __ATOMIC_ACQUIRE) != HOUR ||
               __atomic_load_n(&w->tv.tv_usec, __ATOMIC_ACQUIRE) != 0;
    }
    return __atomic_load_n(&w->ts.tv_sec, __ATOMIC_ACQUIRE) != HOUR ||
           __atomic_load_n(&w->ts.tv_nsec, __ATOMIC_ACQUIRE) != 0;
}

static int timeout_written_or_done(void *arg) { return timeout_written(arg) || is_done(arg); }

// Signals the waiter with ignored SIGCHLDs until it writes back the time left, failing if that
// ends the wait.
static void interrupt_reissued_wait(struct waiter *w) {
    if (!signal_until(SIGCHLD, timeout_written_or_done, w, LIVENESS_MS)) {
        printf("FAIL: %s: no interruption\n", call_name(w->call));
        exit(1);
    }
    expect_waiting(w, "an ignored signal ended the wait");
}

static void expect_time_left(struct waiter *w) {
    long sec = time_left_sec(w);
    if (!timeout_written(w) || sec < 0 || sec > HOUR) {
        printf("FAIL: %s: time left %ld s\n", call_name(w->call), sec);
        exit(1);
    }
}

// An ignored signal interrupts ppoll, select, or pselect6, which writes back the time left, then
// goes on until its fd is ready.
static void test_wait_reissued_after_ignored_signal(enum call call) {
    static struct waiter w;
    start_waiter(&w, call);
    interrupt_reissued_wait(&w);
    TEST_ASSERT(write(w.idle[1], "x", 1) == 1, "write");
    wait_done(&w, SIGCHLD);
    finish_waiter(&w);
    expect_result(&w, 1, 0);
    expect_time_left(&w);
}

// Even with SA_RESTART, a handler interrupts poll, ppoll, select, and pselect6, poll writing back
// the revents and the others the time left, even of a timeout longer than they can wait.
static void test_wait_with_restarting_handler(enum call call) {
    const long huge = 1000L * 1000 * 1000 * 1000;
    set_handler(SIGUSR1, handle_signal, SA_RESTART);
    static struct waiter w;
    init_waiter(&w, call);
    w.fds[0].revents = REVENTS_UNWRITTEN;
    w.ts = (struct timespec){.tv_sec = huge, .tv_nsec = 0};
    w.tv = (struct timeval){.tv_sec = huge, .tv_usec = 0};
    launch_waiter(&w);
    wait_done(&w, SIGUSR1);
    finish_waiter(&w);
    set_handler(SIGUSR1, SIG_DFL, 0);
    expect_result(&w, -1, EINTR);
    if (call == POLL || call == PPOLL) {
        TEST_ASSERT(w.fds[0].revents == 0, "an interrupted poll writes back the revents");
    }
    long sec = time_left_sec(&w);
    if (call != POLL && (sec <= huge - HOUR || sec > huge)) {
        printf("FAIL: %s: %ld s left of %ld s\n", call_name(call), sec, huge);
        exit(1);
    }
}

// A timed-out ppoll, select, or pselect6 writes back no time left.
static void test_timed_out_wait_writes_back_zero(enum call call) {
    struct waiter w;
    init_waiter(&w, call);
    w.ts = (struct timespec){.tv_sec = 0, .tv_nsec = 1000 * 1000};
    w.tv = (struct timeval){.tv_sec = 0, .tv_usec = 1000};
    long ret = do_call(&w);
    close(w.idle[0]);
    close(w.idle[1]);
    TEST_ASSERT(ret == 0, "the wait times out");
    long sec = time_left_sec(&w);
    long frac = call == SELECT ? (long)w.tv.tv_usec : w.ts.tv_nsec;
    if (sec != 0 || frac != 0) {
        printf("FAIL: %s: timed out with %ld.%ld left\n", call_name(call), sec, frac);
        exit(1);
    }
}

static atomic_int handled;
static atomic_int handler_failed;
static sigset_t mask_in_handler;

static void record_signal(int signal) {
    (void)signal;
    if (pthread_sigmask(SIG_BLOCK, NULL, &mask_in_handler) != 0) {
        atomic_store(&handler_failed, 1);
    }
    atomic_store(&handled, 1);
}

static void reset_handled(void) {
    atomic_store(&handled, 0);
    atomic_store(&handler_failed, 0);
}

// Whether the handler ran, and could read its mask.
static int handler_ran(void) {
    TEST_ASSERT(!atomic_load(&handler_failed), "pthread_sigmask in the handler");
    return atomic_load(&handled);
}

static void block_signal(int signal, sigset_t *old) {
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, signal);
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &block, old) == 0, "pthread_sigmask");
}

// Blocks `signal` and makes it pending.
static void block_and_raise(int signal, sigset_t *old) {
    block_signal(signal, old);
    TEST_ASSERT(raise(signal) == 0, "raise");
}

// Calls ppoll or pselect6 in this thread, with no signal blocked for the call, waiting at most
// `*timeout`.
static long call_with_empty_mask(enum call call, struct timespec *timeout) {
    struct waiter w;
    init_waiter(&w, call);
    w.use_mask = 1;
    sigemptyset(&w.mask);
    w.ts_ptr = timeout;
    long ret = do_call(&w);
    int err = errno;
    close(w.idle[0]);
    close(w.idle[1]);
    errno = err;
    return ret;
}

static atomic_int probe_hits;

static void count_probe_hit(int signal) {
    (void)signal;
    atomic_fetch_add(&probe_hits, 1);
}

// Fails unless `signal` is blocked and not pending, which unblocking it under a handler shows.
static void expect_blocked_not_pending(int signal, const char *what) {
    sigset_t mask;
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, NULL, &mask) == 0, "pthread_sigmask");
    int blocked = sigismember(&mask, signal);
    struct sigaction probe, old_action;
    memset(&probe, 0, sizeof(probe));
    probe.sa_handler = count_probe_hit;
    sigemptyset(&probe.sa_mask);
    TEST_ASSERT(sigaction(signal, &probe, &old_action) == 0, "sigaction");
    atomic_store(&probe_hits, 0);
    sigset_t only;
    sigemptyset(&only);
    sigaddset(&only, signal);
    TEST_ASSERT(pthread_sigmask(SIG_UNBLOCK, &only, NULL) == 0, "pthread_sigmask");
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &only, NULL) == 0, "pthread_sigmask");
    TEST_ASSERT(sigaction(signal, &old_action, NULL) == 0, "sigaction");
    int pending = atomic_load(&probe_hits) != 0;
    if (!blocked || pending) {
        printf("FAIL: %s: signal %d blocked=%d pending=%d, expected blocked and not pending\n",
               what, signal, blocked, pending);
        exit(1);
    }
}

// Fails unless the call failed with EINTR after the handler ran with the call's empty mask
// besides its own signal, SIGUSR1, and both SIGUSR1 and SIGCHLD are blocked again and handled.
static void expect_handler_ran_with_call_mask(long ret, int err, const char *what) {
    if (ret != -1 || err != EINTR || !handler_ran()) {
        printf("FAIL: %s with a mask: ret=%ld errno=%d handled=%d, expected EINTR, handled\n",
               what, ret, err, atomic_load(&handled));
        exit(1);
    }
    if (!sigismember(&mask_in_handler, SIGUSR1) || sigismember(&mask_in_handler, SIGCHLD)) {
        printf("FAIL: %s with a mask: SIGUSR1 blocked=%d SIGCHLD blocked=%d in the handler\n",
               what, sigismember(&mask_in_handler, SIGUSR1),
               sigismember(&mask_in_handler, SIGCHLD));
        exit(1);
    }
    expect_blocked_not_pending(SIGUSR1, what);
    expect_blocked_not_pending(SIGCHLD, what);
}

// A signal pending while blocked, which the call's mask unblocks, interrupts ppoll or pselect6
// and reaches its handler, which runs with the call's mask, and whose frame saves the mask from
// before the call.
static void test_call_mask_lets_handler_run(enum call call) {
    set_handler(SIGUSR1, record_signal, 0);
    reset_handled();
    sigset_t old;
    block_and_raise(SIGUSR1, &old);
    block_signal(SIGCHLD, NULL);
    struct timespec timeout = LIVENESS_TIMESPEC;
    errno = 0;
    long ret = call_with_empty_mask(call, &timeout);
    expect_handler_ran_with_call_mask(ret, errno, call_name(call));
    TEST_ASSERT(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0, "pthread_sigmask");
    set_handler(SIGUSR1, SIG_DFL, 0);
}

// An ignored signal pending while blocked, which the call's mask unblocks, interrupts ppoll or
// pselect6, which discards it and is reissued with the time left, timing out. With its timeout in
// read-only memory, the call cannot write back the time left, so it fails with EINTR instead, as
// reissuing it would wait the whole timeout again.
static void test_call_mask_discards_ignored_signal(enum call call) {
    long page = sysconf(_SC_PAGESIZE);
    struct timespec *timeout =
        mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(timeout != MAP_FAILED, "mmap");
    for (int read_only = 0; read_only <= 1; read_only++) {
        TEST_ASSERT(mprotect(timeout, page, PROT_READ | PROT_WRITE) == 0, "mprotect");
        // A read-only timeout bounds how long a broken implementation waits.
        *timeout = read_only ? LIVENESS_TIMESPEC
                             : (struct timespec){.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        if (read_only) {
            TEST_ASSERT(mprotect(timeout, page, PROT_READ) == 0, "mprotect");
        }
        sigset_t old;
        block_and_raise(SIGCHLD, &old);
        errno = 0;
        long ret = call_with_empty_mask(call, timeout);
        int err = errno;
        if (read_only ? ret != -1 || err != EINTR : ret != 0) {
            printf("FAIL: %s with a mask, ignored signal, %s timeout: ret=%ld errno=%d\n",
                   call_name(call), read_only ? "read-only" : "writable", ret, err);
            exit(1);
        }
        expect_blocked_not_pending(SIGCHLD, call_name(call));
        TEST_ASSERT(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0, "pthread_sigmask");
    }
    TEST_ASSERT(munmap(timeout, page) == 0, "munmap");
}

// A ppoll or pselect6 that fails on its arguments after setting its mask restores the mask.
static void test_bad_arguments_restore_mask(enum call call) {
    sigset_t unblock, old, mask;
    sigemptyset(&unblock);
    sigaddset(&unblock, SIGUSR1);
    TEST_ASSERT(pthread_sigmask(SIG_UNBLOCK, &unblock, &old) == 0, "pthread_sigmask");
    struct timespec timeout = {.tv_sec = 5, .tv_nsec = 0};
    struct {
        const sigset_t *mask;
        size_t size;
    } mask_arg = {&unblock, KERNEL_SIGSET_SIZE};
    struct pollfd fds[1] = {{.fd = -1, .events = POLLIN}};
    errno = 0;
    long ret;
    int expected;
    if (call == PPOLL) {
        // More fds than RLIMIT_NOFILE allows.
        ret = syscall(SYS_ppoll, fds, UINT32_MAX, &timeout, &unblock, KERNEL_SIGSET_SIZE);
        expected = EINVAL;
    } else {
        ret = syscall(SYS_pselect6, 1, (void *)1, NULL, NULL, &timeout, &mask_arg);
        expected = EFAULT;
    }
    int err = errno;
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, NULL, &mask) == 0, "pthread_sigmask");
    if (ret != -1 || err != expected || sigismember(&mask, SIGUSR1)) {
        printf("FAIL: %s with bad arguments: ret=%ld errno=%d SIGUSR1 blocked=%d, expected "
               "errno=%d and the mask restored\n",
               call_name(call), ret, err, sigismember(&mask, SIGUSR1), expected);
        exit(1);
    }
    TEST_ASSERT(timeout.tv_sec >= 0 && timeout.tv_sec <= 5 && timeout.tv_nsec >= 0 &&
                    timeout.tv_nsec < 1000L * 1000 * 1000,
                "the time left is valid");
    TEST_ASSERT(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0, "pthread_sigmask");
}

// ppoll and pselect6 ignore the size of a NULL mask, as glibc's pselect passes a NULL mask with
// the size of the kernel's sigset_t.
static void test_null_mask_ignores_size(void) {
    int idle[2];
    TEST_ASSERT(pipe(idle) == 0, "pipe");
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(idle[0], &readfds);
    struct timespec zero = {0};
    TEST_ASSERT(pselect(idle[0] + 1, &readfds, NULL, NULL, &zero, NULL) == 0,
                "glibc pselect with a NULL mask");
    FD_SET(idle[0], &readfds);
    struct {
        const sigset_t *mask;
        size_t size;
    } mask_arg = {NULL, 999};
    TEST_ASSERT(syscall(SYS_pselect6, idle[0] + 1, &readfds, NULL, NULL, &zero, &mask_arg) == 0,
                "pselect6 with a NULL mask of a bad size");
    struct pollfd fds[1] = {{.fd = idle[0], .events = POLLIN}};
    TEST_ASSERT(syscall(SYS_ppoll, fds, 1, &zero, NULL, 999) == 0,
                "ppoll with a NULL mask of a bad size");
    close(idle[0]);
    close(idle[1]);
}

static atomic_int usr2_handled;
static atomic_int usr2_handler_failed;
static sigset_t mask_in_usr2_handler;

static void record_usr2(int signal) {
    (void)signal;
    if (pthread_sigmask(SIG_BLOCK, NULL, &mask_in_usr2_handler) != 0) {
        atomic_store(&usr2_handler_failed, 1);
    }
    atomic_store(&usr2_handled, 1);
}

static int usr2_handled_or_done(void *arg) { return atomic_load(&usr2_handled) || is_done(arg); }

// A signal pending while ppoll or pselect6 blocks it with its mask, but unblocked without it,
// reaches its handler once an ignored signal interrupts the call, before the call is reissued.
// The handler runs with the mask from before the call, which the waiter blocks SIGURG in, and the
// call keeps that mask once it returns.
static void test_restored_mask_lets_handler_run(enum call call) {
    set_handler(SIGUSR2, record_usr2, 0);
    atomic_store(&usr2_handled, 0);
    atomic_store(&usr2_handler_failed, 0);
    static struct waiter w;
    init_waiter(&w, call);
    w.use_mask = 1;
    sigemptyset(&w.mask);
    sigaddset(&w.mask, SIGUSR2);
    launch_waiter(&w);
    // The call is underway once it writes back the time left, so SIGUSR2 all but certainly
    // comes while the call blocks it.
    interrupt_reissued_wait(&w);
    TEST_ASSERT(kill(getpid(), SIGUSR2) == 0, "kill");
    if (!signal_until(SIGCHLD, usr2_handled_or_done, &w, LIVENESS_MS) || is_done(&w)) {
        printf("FAIL: %s with a mask: handled=%d done=%d, expected the handler to run first\n",
               call_name(call), atomic_load(&usr2_handled), is_done(&w));
        exit(1);
    }
    TEST_ASSERT(!atomic_load(&usr2_handler_failed), "pthread_sigmask in the handler");
    if (!sigismember(&mask_in_usr2_handler, SIGURG) ||
        !sigismember(&mask_in_usr2_handler, SIGUSR2)) {
        printf("FAIL: %s with a mask: SIGURG blocked=%d SIGUSR2 blocked=%d in the handler\n",
               call_name(call), sigismember(&mask_in_usr2_handler, SIGURG),
               sigismember(&mask_in_usr2_handler, SIGUSR2));
        exit(1);
    }
    TEST_ASSERT(write(w.idle[1], "x", 1) == 1, "write");
    wait_done(&w, SIGCHLD);
    finish_waiter(&w);
    set_handler(SIGUSR2, SIG_DFL, 0);
    expect_result(&w, 1, 0);
    if (!sigismember(&w.mask_after, SIGURG) || sigismember(&w.mask_after, SIGUSR2)) {
        printf("FAIL: %s with a mask: SIGURG blocked=%d SIGUSR2 blocked=%d after the call\n",
               call_name(call), sigismember(&w.mask_after, SIGURG),
               sigismember(&w.mask_after, SIGUSR2));
        exit(1);
    }
}

// epoll_pwait keeps its mask until the signal that interrupts it is delivered, like ppoll, but
// fails with EINTR even when that signal is ignored.
static void test_epoll_pwait_mask(void) {
    int epfd = epoll_create1(0);
    TEST_ASSERT(epfd >= 0, "epoll_create1");
    int idle[2];
    TEST_ASSERT(pipe(idle) == 0, "pipe");
    struct epoll_event event = {.events = EPOLLIN, .data.fd = idle[0]};
    TEST_ASSERT(epoll_ctl(epfd, EPOLL_CTL_ADD, idle[0], &event) == 0, "epoll_ctl");
    sigset_t empty;
    sigemptyset(&empty);
    struct epoll_event events[1];

    set_handler(SIGUSR1, record_signal, 0);
    reset_handled();
    sigset_t old;
    block_and_raise(SIGUSR1, &old);
    block_signal(SIGCHLD, NULL);
    errno = 0;
    long ret =
        syscall(SYS_epoll_pwait, epfd, events, 1, (int)LIVENESS_MS, &empty, KERNEL_SIGSET_SIZE);
    expect_handler_ran_with_call_mask(ret, errno, "epoll_pwait");
    set_handler(SIGUSR1, SIG_DFL, 0);

    TEST_ASSERT(raise(SIGCHLD) == 0, "raise");
    errno = 0;
    ret = syscall(SYS_epoll_pwait, epfd, events, 1, (int)LIVENESS_MS, &empty, KERNEL_SIGSET_SIZE);
    if (ret != -1 || errno != EINTR) {
        printf("FAIL: epoll_pwait with a mask, ignored signal: ret=%ld errno=%d, expected "
               "EINTR\n",
               ret, errno);
        exit(1);
    }
    expect_blocked_not_pending(SIGCHLD, "epoll_pwait");
    TEST_ASSERT(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0, "pthread_sigmask");
    close(idle[0]);
    close(idle[1]);
    close(epfd);
}

int main(void) {
    printf("Testing wait restarts...\n");
    static const enum call futex_calls[] = {FUTEX_RELATIVE, FUTEX_ABSOLUTE, FUTEX_UNTIMED};
    for (size_t i = 0; i < sizeof(futex_calls) / sizeof(futex_calls[0]); i++) {
        test_futex_wait_survives_ignored_signals(futex_calls[i]);
        test_resumed_futex_wait_checks_word(futex_calls[i]);
        test_futex_wait_with_restarting_handler(futex_calls[i]);
    }
#ifdef SYS_poll
    test_resumed_poll_reads_fds(-1);
    test_resumed_poll_reads_fds(HOUR * 1000);
    test_wait_with_restarting_handler(POLL);
#endif
    static const enum call reissued_calls[] = {
#ifdef SYS_select
        SELECT,
#endif
        PPOLL,
        PSELECT6,
    };
    for (size_t i = 0; i < sizeof(reissued_calls) / sizeof(reissued_calls[0]); i++) {
        test_wait_reissued_after_ignored_signal(reissued_calls[i]);
        test_wait_with_restarting_handler(reissued_calls[i]);
        test_timed_out_wait_writes_back_zero(reissued_calls[i]);
    }
    static const enum call masked_calls[] = {PPOLL, PSELECT6};
    for (size_t i = 0; i < sizeof(masked_calls) / sizeof(masked_calls[0]); i++) {
        test_call_mask_lets_handler_run(masked_calls[i]);
        test_call_mask_discards_ignored_signal(masked_calls[i]);
        test_bad_arguments_restore_mask(masked_calls[i]);
        test_restored_mask_lets_handler_run(masked_calls[i]);
    }
    test_null_mask_ignores_size();
    test_epoll_pwait_mask();
    printf("All wait restart tests passed.\n");
    return 0;
}
