// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that futexes in shared anonymous memory span a parent and its forked children, while
// private futex operations on the same memory, and futexes in private memory, stay within each
// process.

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "helpers.h"

// Bounds every wait, so a failure cannot hang the test.
#define TIMEOUT_SECONDS 30
#define ROUNDS 200

struct shared {
    atomic_uint word;
    atomic_uint ready;
    atomic_uint value;
    // The thread ID that Linux clears, and wakes a waiter on, when the thread exits.
    atomic_uint tid;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    unsigned turn;
    unsigned count;
    sem_t request;
    sem_t reply;
};

static long futex(atomic_uint *word, int op, unsigned value, const struct timespec *timeout) {
    return syscall(SYS_futex, word, op, value, timeout, NULL, 0);
}

static long futex_bitset(atomic_uint *word, int op, unsigned value,
                         const struct timespec *timeout, unsigned bitset) {
    return syscall(SYS_futex, word, op, value, timeout, NULL, bitset);
}

// Returns the CLOCK_MONOTONIC time `ms` milliseconds from now, an absolute bitset-wait deadline.
static struct timespec deadline_in_ms(long ms) {
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += ms / 1000;
    deadline.tv_nsec += (ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000;
    }
    return deadline;
}

// Waits until `*word` holds `value`, returning whether it did before the timeout. Waits on
// another process's stores are bounded, so memory that is not actually shared fails the check
// instead of hanging.
static int await_value(atomic_uint *word, unsigned value) {
    for (int attempt = 0; attempt < TIMEOUT_SECONDS * 1000; attempt++) {
        if (atomic_load(word) == value) {
            return 1;
        }
        sleep_ms(1);
    }
    return atomic_load(word) == value;
}

// Returns whether `child` has exited, reaping it and storing its exit code if so.
static int exited(pid_t child, int *code) {
    int status = 0;
    if (waitpid(child, &status, WNOHANG) != child) {
        return 0;
    }
    *code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return 1;
}

// Futex words in private memory, for waiters that are threads of this process.
static atomic_uint private_futex;

// A waiter on a futex word: a forked child, which can wait on shared memory, or a thread, which
// can also wait on private memory.
struct waiter {
    atomic_uint *word;
    // Counts the waiters about to wait. In shared memory, so that a forked child's store shows.
    atomic_uint *ready;
    unsigned bitset;
    // The forked child, or 0 for a thread.
    pid_t child;
    pthread_t thread;
    // A thread's outcome: 0 while waiting, 1 once woken, or -1 if its wait failed.
    atomic_int outcome;
    int running;
};

static void init_waiter(struct waiter *waiter, atomic_uint *word, atomic_uint *ready,
                        unsigned bitset) {
    waiter->word = word;
    waiter->ready = ready;
    waiter->bitset = bitset;
    waiter->child = 0;
    atomic_store(&waiter->outcome, 0);
    waiter->running = 0;
}

// Waits with `waiter`'s mask until a wake selects it, returning whether one did.
static int wait_until_selected(struct waiter *waiter) {
    struct timespec deadline = deadline_in_ms(TIMEOUT_SECONDS * 1000L);
    atomic_fetch_add(waiter->ready, 1);
    long result;
    do {
        result = futex_bitset(waiter->word, FUTEX_WAIT_BITSET, 0, &deadline, waiter->bitset);
    } while (result == -1 && errno == EINTR);
    return result == 0;
}

static void *wait_in_thread(void *arg) {
    struct waiter *waiter = arg;
    atomic_store(&waiter->outcome, wait_until_selected(waiter) ? 1 : -1);
    return NULL;
}

// Starts `waiter` waiting, in a forked child if `forked` and in a thread otherwise, returning
// whether it started.
static int start_waiter(struct waiter *waiter, int forked) {
    if (forked) {
        pid_t child = fork();
        if (child < 0) {
            return 0;
        }
        if (child == 0) {
            _exit(wait_until_selected(waiter) ? 0 : 1);
        }
        waiter->child = child;
    } else if (pthread_create(&waiter->thread, NULL, wait_in_thread, waiter) != 0) {
        return 0;
    }
    waiter->running = 1;
    return 1;
}

// Returns 1 if `waiter` finished because a wake selected it, -1 if it finished otherwise, and 0
// if it is still waiting. A finished waiter is reaped or joined.
static int poll_waiter(struct waiter *waiter) {
    if (!waiter->running) {
        return -1;
    }
    int outcome = 0;
    if (waiter->child != 0) {
        int code = -1;
        if (!exited(waiter->child, &code)) {
            return 0;
        }
        outcome = code == 0 ? 1 : -1;
    } else {
        outcome = atomic_load(&waiter->outcome);
        if (outcome == 0) {
            return 0;
        }
        pthread_join(waiter->thread, NULL);
    }
    waiter->running = 0;
    return outcome;
}

// Waits for `waiter` to finish, returning `poll_waiter`'s result, or 0 if it did not in time.
static int await_waiter(struct waiter *waiter) {
    for (int attempt = 0; attempt < TIMEOUT_SECONDS * 1000; attempt++) {
        int outcome = poll_waiter(waiter);
        if (outcome != 0) {
            return outcome;
        }
        sleep_ms(1);
    }
    return 0;
}

// Ends `waiter` if it is still running: kills a child, or wakes a thread until it returns.
static void stop_waiter(struct waiter *waiter) {
    if (!waiter->running) {
        return;
    }
    if (waiter->child != 0) {
        reap(waiter->child, 0);
        waiter->running = 0;
        return;
    }
    // The thread's wait is bounded, so this ends even if wakes never reach it.
    while (poll_waiter(waiter) == 0) {
        futex_bitset(waiter->word, FUTEX_WAKE_BITSET, INT_MAX, NULL, FUTEX_BITSET_MATCH_ANY);
        sleep_ms(1);
    }
}

// Wakes `word` with `op`, `count`, and `bitset` until a wake reports waking a waiter, returning
// what the last wake reported.
static long wake_until_woken(atomic_uint *word, int op, unsigned count, unsigned bitset) {
    long woken = 0;
    for (int attempt = 0; attempt < TIMEOUT_SECONDS * 100 && woken == 0; attempt++) {
        woken = futex_bitset(word, op, count, NULL, bitset);
        if (woken == 0) {
            sleep_ms(10);
        }
    }
    return woken;
}

// A child blocked in FUTEX_WAIT on shared memory wakes on its parent's FUTEX_WAKE, which
// reports waking it, but not on wakes of another word in the memory or of the same word in
// `other` shared memory.
static int check_wake(struct shared *shared, struct shared *other) {
    atomic_store(&shared->word, 0);
    atomic_store(&shared->ready, 0);
    pid_t child = fork();
    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        struct timespec timeout = {.tv_sec = TIMEOUT_SECONDS};
        atomic_store(&shared->ready, 1);
        long result;
        do {
            result = futex(&shared->word, FUTEX_WAIT, 0, &timeout);
        } while (result == -1 && errno == EINTR);
        _exit(result == 0 ? 0 : 1);
    }
    if (!await_value(&shared->ready, 1)) {
        reap(child, 0);
        return 0;
    }
    // The word stays zero, so the child returns only when a wake selects it. The wakes that
    // must miss it are repeated with the one that selects it, so some run while it is blocked.
    int ok = 1;
    int code = -1;
    for (int attempt = 0; attempt < TIMEOUT_SECONDS * 100; attempt++) {
        ok &= futex(&shared->value, FUTEX_WAKE, 1, NULL) == 0;
        ok &= futex(&other->word, FUTEX_WAKE, 1, NULL) == 0;
        long woken = futex(&shared->word, FUTEX_WAKE, 1, NULL);
        if (woken == 1) {
            return reap(child, 1) == 0 && ok;
        }
        if (exited(child, &code)) {
            return 0;
        }
        if (woken != 0) {
            break;
        }
        sleep_ms(10);
    }
    reap(child, 0);
    return 0;
}

// Of two waiters on `word`, forked children if `forked` and threads otherwise, a wake with `op`
// and `count` reports waking one, which finishes while the other keeps waiting, and a wake of all
// then reports waking the other. Linux takes the count as an `int` and counts a waiter before
// comparing, so a count that is zero or negative as an `int` wakes one waiter.
static int check_count_case(atomic_uint *word, atomic_uint *ready, int forked, int op,
                            unsigned count) {
    atomic_store(word, 0);
    atomic_store(ready, 0);
    struct waiter waiters[2];
    int ok = 1;
    for (int index = 0; index < 2; index++) {
        init_waiter(&waiters[index], word, ready, FUTEX_BITSET_MATCH_ANY);
        ok = ok && start_waiter(&waiters[index], forked);
    }
    ok = ok && await_value(ready, 2);
    // Let both block, so that the first wake has two waiters to choose from.
    sleep_ms(100);
    int first = -1;
    if (ok && wake_until_woken(word, op, count, FUTEX_BITSET_MATCH_ANY) == 1) {
        for (int attempt = 0; attempt < TIMEOUT_SECONDS * 1000 && first == -1; attempt++) {
            for (int index = 0; index < 2 && first == -1; index++) {
                int outcome = poll_waiter(&waiters[index]);
                if (outcome != 0) {
                    first = outcome == 1 ? index : -2;
                }
            }
            if (first == -1) {
                sleep_ms(1);
            }
        }
    }
    ok = first >= 0;
    if (ok) {
        sleep_ms(50);
        ok = poll_waiter(&waiters[1 - first]) == 0 &&
             wake_until_woken(word, op, INT_MAX, FUTEX_BITSET_MATCH_ANY) == 1 &&
             await_waiter(&waiters[1 - first]) == 1;
    }
    stop_waiter(&waiters[0]);
    stop_waiter(&waiters[1]);
    return ok;
}

// Counts behave alike for FUTEX_WAKE and FUTEX_WAKE_BITSET, across forked children waiting on
// shared memory and threads waiting on private memory.
static int check_count(struct shared *shared) {
    static const int ops[] = {FUTEX_WAKE, FUTEX_WAKE_BITSET};
    static const unsigned counts[] = {0, 0x80000000u, 0xffffffffu};
    int ok = 1;
    for (int forked = 0; forked <= 1; forked++) {
        atomic_uint *word = forked ? &shared->word : &private_futex;
        for (size_t op = 0; op < sizeof(ops) / sizeof(ops[0]); op++) {
            for (size_t count = 0; count < sizeof(counts) / sizeof(counts[0]); count++) {
                int passed = check_count_case(word, &shared->ready, forked, ops[op], counts[count]);
                if (!passed) {
                    fprintf(stderr, "count failed: forked=%d op=%d count=%#x\n", forked, ops[op],
                            counts[count]);
                }
                ok &= passed;
            }
        }
    }
    return ok;
}

// A non-private futex in private memory is keyed by process, so after fork the parent's wake of
// a copy-on-write word never reaches the child's waiter on its copy.
static int check_private_memory(struct shared *shared) {
    atomic_uint *word = mmap(NULL, sizeof(*word), PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (word == MAP_FAILED) {
        return 0;
    }
    atomic_store(word, 0);
    atomic_store(&shared->ready, 0);
    pid_t child = fork();
    if (child < 0) {
        munmap(word, sizeof(*word));
        return 0;
    }
    if (child == 0) {
        struct timespec timeout = {.tv_nsec = 300 * 1000000};
        atomic_store(&shared->ready, 1);
        long result = futex(word, FUTEX_WAIT, 0, &timeout);
        _exit(result == -1 && errno == ETIMEDOUT ? 0 : 1);
    }
    int ok = await_value(&shared->ready, 1);
    for (int attempt = 0; attempt < 10 && ok; attempt++) {
        ok &= futex(word, FUTEX_WAKE, 1, NULL) == 0;
        sleep_ms(10);
    }
    munmap(word, sizeof(*word));
    return reap(child, ok) == 0 && ok;
}

static char clear_tid_stack[64 * 1024] __attribute__((aligned(16)));
// The thread's own thread pointer target, which, like x86-64's thread control block, points to
// itself, so that the thread does not share its creator's.
static void *clear_tid_tls[512] __attribute__((aligned(64)));

// Exits once released, so that Linux clears and wakes the thread ID it was created with.
static int exit_when_released(void *arg) {
    struct shared *shared = arg;
    while (atomic_load(&shared->value) == 0) {
        syscall(SYS_sched_yield);
    }
    return 0;
}

// When a thread whose clear_child_tid word is in shared memory exits, Linux clears the word and
// wakes a waiter on it in another process, as a non-private futex.
static int check_clear_tid(struct shared *shared) {
    atomic_store(&shared->value, 0);
    atomic_store(&shared->ready, 0);
    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
                CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
    clear_tid_tls[0] = clear_tid_tls;
    pid_t thread = clone(exit_when_released, clear_tid_stack + sizeof(clear_tid_stack), flags,
                         shared, (pid_t *)&shared->tid, clear_tid_tls, (pid_t *)&shared->tid);
    if (thread <= 0) {
        return 0;
    }
    pid_t child = fork();
    if (child < 0) {
        atomic_store(&shared->value, 1);
        await_value(&shared->tid, 0);
        return 0;
    }
    if (child == 0) {
        struct timespec timeout = {.tv_sec = TIMEOUT_SECONDS};
        atomic_store(&shared->ready, 1);
        for (;;) {
            unsigned tid = atomic_load(&shared->tid);
            if (tid == 0) {
                _exit(0);
            }
            if (futex(&shared->tid, FUTEX_WAIT, tid, &timeout) == -1 && errno == ETIMEDOUT) {
                _exit(1);
            }
        }
    }
    int ok = await_value(&shared->ready, 1);
    // Let the child block, so that only the wake on exit can release it.
    sleep_ms(100);
    atomic_store(&shared->value, 1);
    ok &= await_value(&shared->tid, 0);
    return reap(child, ok) == 0 && ok;
}

// A FUTEX_WAIT on shared memory times out, and fails at once if the word changed.
static int check_timeout(struct shared *shared) {
    atomic_store(&shared->word, 7);
    struct timespec timeout = {.tv_nsec = 50 * 1000000};
    return futex(&shared->word, FUTEX_WAIT, 7, &timeout) == -1 && errno == ETIMEDOUT &&
           futex(&shared->word, FUTEX_WAIT, 0, &timeout) == -1 && errno == EAGAIN;
}

static void ignore_signal(int signal) {
    (void)signal;
}

// Like Linux, a signal whose handler does not restart system calls interrupts a shared wait with
// EINTR, and the interrupted waiter is no longer queued, so a later wake finds no waiter.
static int check_interrupted(struct shared *shared) {
    atomic_store(&shared->word, 0);
    atomic_store(&shared->value, 0);
    pid_t child = fork();
    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        struct sigaction action = {.sa_handler = ignore_signal};
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR1, &action, NULL) != 0) {
            _exit(1);
        }
        atomic_store(&shared->value, 1);
        struct timespec timeout = {.tv_sec = TIMEOUT_SECONDS};
        int interrupted = futex(&shared->word, FUTEX_WAIT, 0, &timeout) == -1 && errno == EINTR;
        atomic_store(&shared->value, 2);
        _exit(interrupted && await_value(&shared->value, 3) ? 0 : 1);
    }
    // Signal until the wait ends, as a signal that arrives before the child waits is handled
    // without interrupting it.
    int ok = await_value(&shared->value, 1);
    for (int attempt = 0; ok && atomic_load(&shared->value) != 2 && attempt < TIMEOUT_SECONDS * 100;
         attempt++) {
        kill(child, SIGUSR1);
        sleep_ms(10);
    }
    ok = ok && atomic_load(&shared->value) == 2 && futex(&shared->word, FUTEX_WAKE, 1, NULL) == 0;
    atomic_store(&shared->value, 3);
    return reap(child, ok) == 0 && ok;
}

// Like any futex operation, one on a misaligned word fails, whether shared or private, and even
// a wake of no waiters.
static int check_misaligned(struct shared *shared) {
    atomic_uint *misaligned = (atomic_uint *)((char *)&shared->word + 2);
    struct timespec timeout = {.tv_nsec = 10 * 1000000};
    int ok = 1;
    for (int flag = 0; flag <= FUTEX_PRIVATE_FLAG; flag += FUTEX_PRIVATE_FLAG) {
        for (unsigned count = 0; count <= 1; count++) {
            ok &= futex(misaligned, FUTEX_WAKE | flag, count, NULL) == -1 && errno == EINVAL;
        }
        ok &= futex(misaligned, FUTEX_WAIT | flag, 0, &timeout) == -1 && errno == EINVAL;
    }
    return ok;
}

// Private futex operations on shared memory are keyed by process, so a parent's private wake
// never reaches its child's private waiter.
static int check_private(struct shared *shared) {
    atomic_store(&shared->word, 0);
    atomic_store(&shared->ready, 0);
    pid_t child = fork();
    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        struct timespec timeout = {.tv_nsec = 300 * 1000000};
        atomic_store(&shared->ready, 1);
        long result = futex(&shared->word, FUTEX_WAIT_PRIVATE, 0, &timeout);
        _exit(result == -1 && errno == ETIMEDOUT ? 0 : 1);
    }
    if (!await_value(&shared->ready, 1)) {
        reap(child, 0);
        return 0;
    }
    int ok = 1;
    for (int attempt = 0; attempt < 10; attempt++) {
        ok &= futex(&shared->word, FUTEX_WAKE_PRIVATE, 1, NULL) == 0;
        sleep_ms(10);
    }
    return reap(child, 1) == 0 && ok;
}

struct keyed_waiter {
    struct shared *shared;
    int op;
    long result;
};

static void *wait_keyed(void *arg) {
    struct keyed_waiter *waiter = arg;
    struct timespec timeout = {.tv_sec = TIMEOUT_SECONDS};
    atomic_store(&waiter->shared->ready, 1);
    do {
        waiter->result = futex(&waiter->shared->word, waiter->op, 0, &timeout);
    } while (waiter->result == -1 && errno == EINTR);
    return NULL;
}

// Within one process, a thread waiting with `wait_op` on shared memory is woken by `wake_op` but
// not by `other_wake_op`, since Linux keys private and shared futexes differently.
static int check_keyed(struct shared *shared, int wait_op, int wake_op, int other_wake_op) {
    atomic_store(&shared->word, 0);
    atomic_store(&shared->ready, 0);
    struct keyed_waiter waiter = {.shared = shared, .op = wait_op, .result = -1};
    pthread_t thread;
    if (pthread_create(&thread, NULL, wait_keyed, &waiter) != 0) {
        return 0;
    }
    int ok = await_value(&shared->ready, 1);
    for (int attempt = 0; attempt < 10; attempt++) {
        ok &= futex(&shared->word, other_wake_op, 1, NULL) == 0;
        sleep_ms(5);
    }
    // The wake that must miss the waiter is repeated with the one that selects it, so some run
    // while it is blocked.
    long woken = 0;
    for (int attempt = 0; attempt < TIMEOUT_SECONDS * 100 && woken == 0 && ok; attempt++) {
        ok &= futex(&shared->word, other_wake_op, 1, NULL) == 0;
        woken = futex(&shared->word, wake_op, 1, NULL);
        if (woken == 0) {
            sleep_ms(10);
        }
    }
    pthread_join(thread, NULL);
    return ok && woken == 1 && waiter.result == 0;
}

// A wake whose mask misses the mask of a waiter on `word`, a forked child if `forked` and a
// thread otherwise, never selects it, and one whose mask intersects it does.
static int check_bitset_selection(atomic_uint *word, atomic_uint *ready, int forked) {
    atomic_store(word, 0);
    atomic_store(ready, 0);
    struct waiter waiter;
    init_waiter(&waiter, word, ready, 0x1);
    int ok = start_waiter(&waiter, forked) && await_value(ready, 1);
    for (int attempt = 0; attempt < 10 && ok; attempt++) {
        ok &= futex_bitset(word, FUTEX_WAKE_BITSET, 1, NULL, 0x2) == 0;
        sleep_ms(5);
    }
    // The wake that must miss the waiter is repeated with the one that selects it, so some run
    // while it is blocked.
    long woken = 0;
    for (int attempt = 0; attempt < TIMEOUT_SECONDS * 100 && woken == 0 && ok; attempt++) {
        ok &= futex_bitset(word, FUTEX_WAKE_BITSET, 1, NULL, 0x2) == 0;
        woken = futex_bitset(word, FUTEX_WAKE_BITSET, 1, NULL, 0x3);
        if (woken == 0) {
            sleep_ms(10);
        }
    }
    ok = ok && woken == 1 && await_waiter(&waiter) == 1;
    stop_waiter(&waiter);
    return ok;
}

// Bitset operations: a zero mask fails, in shared or private memory, a wait honors its absolute
// deadline, and a wake selects only waiters whose masks intersect its own, whether a forked
// child's on shared memory or a thread's on private memory.
static int check_bitset(struct shared *shared) {
    atomic_store(&shared->word, 0);
    struct timespec deadline = deadline_in_ms(50);
    int ok = 1;
    atomic_uint *words[] = {&shared->word, &private_futex};
    for (int index = 0; index < 2; index++) {
        for (int flag = 0; flag <= FUTEX_PRIVATE_FLAG; flag += FUTEX_PRIVATE_FLAG) {
            ok &= futex_bitset(words[index], FUTEX_WAIT_BITSET | flag, 0, &deadline, 0) == -1 &&
                  errno == EINVAL;
            ok &= futex_bitset(words[index], FUTEX_WAKE_BITSET | flag, 1, NULL, 0) == -1 &&
                  errno == EINVAL;
        }
    }
    ok &= futex_bitset(&shared->word, FUTEX_WAIT_BITSET, 0, &deadline, 1) == -1 &&
          errno == ETIMEDOUT;
    return ok && check_bitset_selection(&shared->word, &shared->ready, 1) &&
           check_bitset_selection(&private_futex, &shared->ready, 0);
}

// Like Linux, a non-private wake of a futex in shared memory this process cannot access fails,
// even with no waiters or a count of zero, and leaves a waiter in another process that can access
// it waiting. A private wake never looks at the mapping, whether shared or private.
static int check_inaccessible(struct shared *shared) {
    long page = sysconf(_SC_PAGESIZE);
    atomic_uint *word = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    atomic_uint *private_word =
        mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (word == MAP_FAILED || private_word == MAP_FAILED) {
        return 0;
    }
    atomic_store(word, 0);
    atomic_store(&shared->ready, 0);
    struct waiter waiter;
    init_waiter(&waiter, word, &shared->ready, FUTEX_BITSET_MATCH_ANY);
    int ok = start_waiter(&waiter, 1) && await_value(&shared->ready, 1);
    // Let the child block, so that a wrongly delivered wake would release it.
    sleep_ms(100);
    ok = ok && mprotect(word, page, PROT_NONE) == 0 && mprotect(private_word, page, PROT_NONE) == 0;
    static const int ops[] = {FUTEX_WAKE, FUTEX_WAKE_BITSET};
    for (unsigned count = 0; count <= 1 && ok; count++) {
        for (size_t op = 0; op < sizeof(ops) / sizeof(ops[0]); op++) {
            ok &= futex_bitset(word, ops[op], count, NULL, FUTEX_BITSET_MATCH_ANY) == -1 &&
                  errno == EFAULT;
            ok &= futex_bitset(word, ops[op] | FUTEX_PRIVATE_FLAG, count, NULL,
                               FUTEX_BITSET_MATCH_ANY) == 0;
            ok &= futex_bitset(private_word, ops[op] | FUTEX_PRIVATE_FLAG, count, NULL,
                               FUTEX_BITSET_MATCH_ANY) == 0;
        }
    }
    // A wait faults like a wake, and a misaligned word fails before its mapping is looked at.
    struct timespec timeout = {.tv_nsec = 10 * 1000000};
    ok &= futex(word, FUTEX_WAIT, 0, &timeout) == -1 && errno == EFAULT;
    ok &= futex((atomic_uint *)((char *)word + 2), FUTEX_WAKE, 1, NULL) == -1 && errno == EINVAL;
    sleep_ms(50);
    ok = ok && poll_waiter(&waiter) == 0;
    // Once accessible again, a wake reaches the waiter the failed wakes left waiting.
    ok = ok && mprotect(word, page, PROT_READ | PROT_WRITE) == 0 &&
         wake_until_woken(word, FUTEX_WAKE, 1, 0) == 1 && await_waiter(&waiter) == 1;
    stop_waiter(&waiter);
    munmap(word, page);
    munmap(private_word, page);
    return ok;
}

// A parent and child take turns under a process-shared mutex and condition variable.
static int check_mutex(struct shared *shared) {
    pthread_mutexattr_t mutex_attr;
    pthread_condattr_t cond_attr;
    if (pthread_mutexattr_init(&mutex_attr) != 0 ||
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_mutex_init(&shared->mutex, &mutex_attr) != 0 ||
        pthread_condattr_init(&cond_attr) != 0 ||
        pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_cond_init(&shared->cond, &cond_attr) != 0) {
        return 0;
    }
    shared->turn = 0;
    shared->count = 0;
    pid_t child = fork();
    if (child < 0) {
        return 0;
    }
    unsigned me = child == 0 ? 1 : 0;
    for (int round = 0; round < ROUNDS; round++) {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += TIMEOUT_SECONDS;
        pthread_mutex_lock(&shared->mutex);
        int error = 0;
        while (shared->turn != me && error == 0) {
            error = pthread_cond_timedwait(&shared->cond, &shared->mutex, &deadline);
        }
        if (error != 0) {
            pthread_mutex_unlock(&shared->mutex);
            if (child == 0) {
                _exit(1);
            }
            reap(child, 0);
            return 0;
        }
        shared->count++;
        shared->turn = 1 - me;
        pthread_cond_broadcast(&shared->cond);
        pthread_mutex_unlock(&shared->mutex);
    }
    if (child == 0) {
        _exit(0);
    }
    return reap(child, 1) == 0 && shared->count == 2 * ROUNDS;
}

// A child blocked on a process-shared semaphore wakes on its parent's post, and its post wakes
// the parent.
static int check_semaphore(struct shared *shared) {
    if (sem_init(&shared->request, 1, 0) != 0 || sem_init(&shared->reply, 1, 0) != 0) {
        return 0;
    }
    pid_t child = fork();
    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        for (int round = 0; round < ROUNDS; round++) {
            while (sem_wait(&shared->request) != 0) {
                if (errno != EINTR) {
                    _exit(1);
                }
            }
            sem_post(&shared->reply);
        }
        _exit(0);
    }
    int ok = 1;
    for (int round = 0; round < ROUNDS && ok; round++) {
        if (round == 0) {
            // Let the child block first.
            sleep_ms(100);
        }
        sem_post(&shared->request);
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += TIMEOUT_SECONDS;
        int result;
        do {
            result = sem_timedwait(&shared->reply, &deadline);
        } while (result != 0 && errno == EINTR);
        ok = result == 0;
    }
    return reap(child, ok) == 0 && ok;
}

// The memory itself is shared: each process sees the other's later stores.
static int check_memory(struct shared *shared) {
    atomic_store(&shared->value, 0);
    pid_t child = fork();
    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        if (!await_value(&shared->value, 1)) {
            _exit(1);
        }
        atomic_store(&shared->value, 2);
        _exit(0);
    }
    atomic_store(&shared->value, 1);
    return reap(child, 1) == 0 && await_value(&shared->value, 2);
}

int main(void) {
    struct shared *shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    struct shared *other = mmap(NULL, sizeof(*other), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED || other == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    int memory = check_memory(shared);
    int wake = check_wake(shared, other);
    int timeout = check_timeout(shared);
    int interrupted = check_interrupted(shared);
    int private = check_private(shared) &&
                  check_keyed(shared, FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAKE_PRIVATE) &&
                  check_keyed(shared, FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE, FUTEX_WAKE);
    int mutex = check_mutex(shared);
    int semaphore = check_semaphore(shared);
    int bitset = check_bitset(shared);
    int misaligned = check_misaligned(shared);
    int count = check_count(shared);
    int inaccessible = check_inaccessible(shared);
    int private_memory = check_private_memory(shared);
    int clear_tid = check_clear_tid(shared);
    printf("shared-futex memory=%d wake=%d timeout=%d interrupted=%d private=%d mutex=%d "
           "semaphore=%d bitset=%d misaligned=%d count=%d inaccessible=%d private-memory=%d "
           "clear-tid=%d\n",
           memory, wake, timeout, interrupted, private, mutex, semaphore, bitset, misaligned,
           count, inaccessible, private_memory, clear_tid);
    return memory && wake && timeout && interrupted && private && mutex && semaphore && bitset &&
                   misaligned && count && inaccessible && private_memory && clear_tid
               ? 0
               : 1;
}
