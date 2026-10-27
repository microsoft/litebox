// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that futexes in shared anonymous memory span a parent and its forked child, while
// private futex operations on the same memory stay within each process.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
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

// Bounds every wait, so a failure cannot hang the test.
#define TIMEOUT_SECONDS 30
#define ROUNDS 200

struct shared {
    atomic_uint word;
    atomic_uint ready;
    atomic_uint value;
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

static void sleep_ms(long ms) {
    struct timespec duration = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000};
    while (nanosleep(&duration, &duration) == -1 && errno == EINTR) {
    }
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

// Returns the exit code of `child`, or -1 if it did not exit normally.
static int reap(pid_t child) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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
        kill(child, SIGKILL);
        reap(child);
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
            return reap(child) == 0 && ok;
        }
        if (woken != 0 || exited(child, &code)) {
            if (code == -1) {
                kill(child, SIGKILL);
                reap(child);
            }
            return 0;
        }
        sleep_ms(10);
    }
    kill(child, SIGKILL);
    reap(child);
    return 0;
}

// A FUTEX_WAIT on shared memory times out, and fails at once if the word changed.
static int check_timeout(struct shared *shared) {
    atomic_store(&shared->word, 7);
    struct timespec timeout = {.tv_nsec = 50 * 1000000};
    return futex(&shared->word, FUTEX_WAIT, 7, &timeout) == -1 && errno == ETIMEDOUT &&
           futex(&shared->word, FUTEX_WAIT, 0, &timeout) == -1 && errno == EAGAIN;
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
        kill(child, SIGKILL);
        reap(child);
        return 0;
    }
    int ok = 1;
    for (int attempt = 0; attempt < 10; attempt++) {
        ok &= futex(&shared->word, FUTEX_WAKE_PRIVATE, 1, NULL) == 0;
        sleep_ms(10);
    }
    return reap(child) == 0 && ok;
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

// Bitset operations: a zero mask fails, in shared or private memory, a wait honors its absolute
// deadline, and a wake selects only waiters whose masks intersect its own, including a forked
// child's.
static int check_bitset(struct shared *shared) {
    atomic_store(&shared->word, 0);
    atomic_store(&shared->ready, 0);
    struct timespec deadline = deadline_in_ms(50);
    int ok = 1;
    atomic_uint private_word = 0;
    atomic_uint *words[] = {&shared->word, &private_word};
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
    if (!ok) {
        return 0;
    }
    pid_t child = fork();
    if (child < 0) {
        return 0;
    }
    if (child == 0) {
        struct timespec child_deadline = deadline_in_ms(TIMEOUT_SECONDS * 1000);
        atomic_store(&shared->ready, 1);
        long result;
        do {
            result = futex_bitset(&shared->word, FUTEX_WAIT_BITSET, 0, &child_deadline, 0x1);
        } while (result == -1 && errno == EINTR);
        _exit(result == 0 ? 0 : 1);
    }
    if (!await_value(&shared->ready, 1)) {
        kill(child, SIGKILL);
        reap(child);
        return 0;
    }
    // A wake whose mask misses the waiter's never selects it.
    for (int attempt = 0; attempt < 10; attempt++) {
        ok &= futex_bitset(&shared->word, FUTEX_WAKE_BITSET, 1, NULL, 0x2) == 0;
        sleep_ms(5);
    }
    long woken = 0;
    for (int attempt = 0; attempt < TIMEOUT_SECONDS * 100 && woken == 0 && ok; attempt++) {
        ok &= futex_bitset(&shared->word, FUTEX_WAKE_BITSET, 1, NULL, 0x2) == 0;
        woken = futex_bitset(&shared->word, FUTEX_WAKE_BITSET, 1, NULL, 0x3);
        if (woken == 0) {
            sleep_ms(10);
        }
    }
    if (woken != 1) {
        kill(child, SIGKILL);
        reap(child);
        return 0;
    }
    return reap(child) == 0 && ok;
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
            kill(child, SIGKILL);
            reap(child);
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
    return reap(child) == 0 && shared->count == 2 * ROUNDS;
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
    if (!ok) {
        kill(child, SIGKILL);
    }
    return reap(child) == 0 && ok;
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
    return reap(child) == 0 && await_value(&shared->value, 2);
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
    int private = check_private(shared) &&
                  check_keyed(shared, FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAKE_PRIVATE) &&
                  check_keyed(shared, FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE, FUTEX_WAKE);
    int mutex = check_mutex(shared);
    int semaphore = check_semaphore(shared);
    int bitset = check_bitset(shared);
    int misaligned = check_misaligned(shared);
    printf("shared-futex memory=%d wake=%d timeout=%d private=%d mutex=%d semaphore=%d "
           "bitset=%d misaligned=%d\n",
           memory, wake, timeout, private, mutex, semaphore, bitset, misaligned);
    return memory && wake && timeout && private && mutex && semaphore && bitset && misaligned
               ? 0
               : 1;
}
