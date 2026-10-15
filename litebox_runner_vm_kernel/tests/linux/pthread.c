// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// For threads (`clone` with `CLONE_THREAD`) in stacked runners. The first
// argument picks a mode:
// - "basic": a mutex-protected counter, thread-local storage, a condition
//   variable ping-pong, a sleeping thread, a thread busy-waiting (no
//   syscalls) for one it created (also after a broker call) or woke (also
//   while another thread waits with a distant timeout), and threads
//   computing at once (preempted, with their own rounding modes); prints
//   `basic: ok`.
// - "exit": one thread calls `exit(7)` while others spin (in guest code) or
//   wait forever, and the main thread waits to join one of them.
// - "detach": the main thread exits with `pthread_exit`; a detached thread
//   then prints and ends the process (status 0).
// - "input": prints `ready`, for the host to send console input (see
//   pthread.input.txt), which a thread waits for (blocking read) while the
//   main thread waits to join it, and another waits on a condition variable
//   with a timeout: every thread blocks.
// - "alarm": a thread waits for `SIGALRM` in `pause`; the main thread sets
//   an alarm, then exits with `pthread_exit`: the waiting thread takes it,
//   prints `alarm: ok`, and ends the process (status 0).
// See pthread.json.

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <xmmintrin.h>

#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__,     \
                    __LINE__, #cond);                                  \
            exit(1);                                                   \
        }                                                              \
    } while (0)

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0) {
    }
}

// Counter.
#define COUNTER_THREADS 4
#define INCREMENTS 20000
static pthread_mutex_t counter_lock = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static __thread long tls_value;

static void *count(void *arg) {
    tls_value = (long)arg;
    for (int i = 0; i < INCREMENTS; i++) {
        pthread_mutex_lock(&counter_lock);
        counter++;
        pthread_mutex_unlock(&counter_lock);
        if (i % 1000 == 0) {
            sched_yield();
        }
    }
    // Another thread's would show here.
    CHECK(tls_value == (long)arg);
    return (void *)(tls_value * 2);
}

// Ping-pong.
#define ROUNDS 500
static pthread_mutex_t pp_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pp_cond = PTHREAD_COND_INITIALIZER;
static int pp_turn; // 0: main's turn, 1: the other's
static int pp_done;

static void *pong(void *arg) {
    (void)arg;
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&pp_lock);
        while (pp_turn != 1) {
            pthread_cond_wait(&pp_cond, &pp_lock);
        }
        pp_turn = 0;
        pp_done++;
        pthread_cond_broadcast(&pp_cond);
        pthread_mutex_unlock(&pp_lock);
    }
    return NULL;
}

static volatile int flag;

static void *set_flag(void *arg) {
    (void)arg;
    flag = 1;
    return NULL;
}

// Waiting for `wake_flag`, then sets `flag`; or, with a timeout, until
// `wake_flag` is 2.
static pthread_mutex_t wake_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake_cond = PTHREAD_COND_INITIALIZER;
static int wake_flag;
static int waiting;

static void *wait_then_set_flag(void *arg) {
    (void)arg;
    pthread_mutex_lock(&wake_lock);
    waiting++;
    while (wake_flag == 0) {
        pthread_cond_wait(&wake_cond, &wake_lock);
    }
    pthread_mutex_unlock(&wake_lock);
    flag = 1;
    return NULL;
}

static void *wait_long(void *arg) {
    (void)arg;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 30;
    pthread_mutex_lock(&wake_lock);
    waiting++;
    while (wake_flag != 2) {
        pthread_cond_timedwait(&wake_cond, &wake_lock, &deadline);
    }
    pthread_mutex_unlock(&wake_lock);
    return NULL;
}

static void *sleeper(void *arg) {
    long long start = now_us();
    sleep_ms((long)arg);
    return (void *)(now_us() - start);
}

// Computing at once.
static double step(double x) {
    return x * 1.000000119 + 0.5;
}

struct spin {
    unsigned int round;
    long long ms;
    double expected;
    int ok;
};

static void *spin(void *arg) {
    struct spin *s = arg;
    // A new thread's SIMD exceptions are masked, as the default (and as
    // its creator's, which Linux gives it).
    CHECK((_mm_getcsr() & _MM_MASK_MASK) == _MM_MASK_MASK);
    _mm_setcsr((_mm_getcsr() & ~_MM_ROUND_MASK) | s->round);
    double x = 1.0;
    long long steps = 0;
    long long start = now_us();
    while (now_us() - start < s->ms * 1000) {
        x = step(x);
        steps++;
    }
    // Recompute: the same steps in the same mode give the same result.
    double y = 1.0;
    for (long long i = 0; i < steps; i++) {
        y = step(y);
    }
    s->ok = (_mm_getcsr() & _MM_ROUND_MASK) == s->round && x == y;
    return NULL;
}

static int basic(void) {
    pthread_t threads[COUNTER_THREADS];
    tls_value = -1;
    for (long i = 0; i < COUNTER_THREADS; i++) {
        CHECK(pthread_create(&threads[i], NULL, count, (void *)(i + 1)) == 0);
    }
    for (long i = 0; i < COUNTER_THREADS; i++) {
        void *result;
        CHECK(pthread_join(threads[i], &result) == 0);
        CHECK((long)result == 2 * (i + 1));
    }
    CHECK(counter == COUNTER_THREADS * INCREMENTS);
    CHECK(tls_value == -1);

    pthread_t other;
    CHECK(pthread_create(&other, NULL, pong, NULL) == 0);
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&pp_lock);
        pp_turn = 1;
        pthread_cond_broadcast(&pp_cond);
        while (pp_turn != 0) {
            pthread_cond_wait(&pp_cond, &pp_lock);
        }
        pthread_mutex_unlock(&pp_lock);
    }
    CHECK(pthread_join(other, NULL) == 0);
    CHECK(pp_done == ROUNDS);

    // The main thread, alone until then, must not keep the new one from
    // running.
    CHECK(pthread_create(&other, NULL, set_flag, NULL) == 0);
    while (!flag) {
    }
    CHECK(pthread_join(other, NULL) == 0);

    // Nor once it makes a broker call that is served at once.
    flag = 0;
    CHECK(pthread_create(&other, NULL, set_flag, NULL) == 0);
    int fd = open("/pthread", O_RDONLY);
    CHECK(fd >= 0 && close(fd) == 0);
    while (!flag) {
    }
    CHECK(pthread_join(other, NULL) == 0);

    // Nor the one it wakes, while another waits with a distant timeout.
    flag = 0;
    pthread_t waiter, long_waiter;
    CHECK(pthread_create(&long_waiter, NULL, wait_long, NULL) == 0);
    CHECK(pthread_create(&waiter, NULL, wait_then_set_flag, NULL) == 0);
    for (;;) {
        pthread_mutex_lock(&wake_lock);
        int both = waiting == 2;
        pthread_mutex_unlock(&wake_lock);
        if (both) {
            break;
        }
        sleep_ms(1);
    }
    sleep_ms(20); // for both to block in the kernel
    long long woken_at = now_us();
    pthread_mutex_lock(&wake_lock);
    wake_flag = 1;
    pthread_cond_broadcast(&wake_cond);
    pthread_mutex_unlock(&wake_lock);
    while (!flag) {
    }
    CHECK(now_us() - woken_at < 5000000);
    CHECK(pthread_join(waiter, NULL) == 0);
    pthread_mutex_lock(&wake_lock);
    wake_flag = 2;
    pthread_cond_broadcast(&wake_cond);
    pthread_mutex_unlock(&wake_lock);
    CHECK(pthread_join(long_waiter, NULL) == 0);

    // A sleeping thread, while the main thread spins.
    CHECK(pthread_create(&other, NULL, sleeper, (void *)50L) == 0);
    long long start = now_us();
    while (now_us() - start < 20000) {
    }
    void *slept;
    CHECK(pthread_join(other, &slept) == 0);
    CHECK((long long)slept >= 50000);

    struct spin spins[3] = {
        {_MM_ROUND_UP, 100, 0, 0},
        {_MM_ROUND_DOWN, 100, 0, 0},
        {_MM_ROUND_TOWARD_ZERO, 100, 0, 0},
    };
    pthread_t spinners[3];
    for (int i = 0; i < 3; i++) {
        CHECK(pthread_create(&spinners[i], NULL, spin, &spins[i]) == 0);
    }
    for (int i = 0; i < 3; i++) {
        CHECK(pthread_join(spinners[i], NULL) == 0);
        CHECK(spins[i].ok);
    }
    printf("basic: ok\n");
    return 0;
}

static void *spin_forever(void *arg) {
    (void)arg;
    volatile unsigned long n = 0;
    for (;;) {
        n++;
    }
    return NULL;
}

static void *wait_forever(void *arg) {
    (void)arg;
    pthread_mutex_lock(&pp_lock);
    for (;;) {
        pthread_cond_wait(&pp_cond, &pp_lock);
    }
    return NULL;
}

static void *exit_soon(void *arg) {
    (void)arg;
    sleep_ms(50);
    exit(7);
}

static int exit_mode(void) {
    pthread_t spinner, waiter, exiter;
    CHECK(pthread_create(&spinner, NULL, spin_forever, NULL) == 0);
    CHECK(pthread_create(&waiter, NULL, wait_forever, NULL) == 0);
    CHECK(pthread_create(&exiter, NULL, exit_soon, NULL) == 0);
    pthread_join(spinner, NULL);
    return 1;
}

static void *detached(void *arg) {
    (void)arg;
    sleep_ms(50);
    printf("detached: done\n");
    fflush(stdout);
    return NULL;
}

static int detach_mode(void) {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    CHECK(pthread_create(&thread, &attr, detached, NULL) == 0);
    pthread_exit(NULL);
}

static void *read_line(void *arg) {
    char *line = arg;
    size_t len = 0;
    while (len < 63 && (len == 0 || line[len - 1] != '\n')) {
        ssize_t n = read(0, line + len, 63 - len);
        if (n <= 0) {
            break;
        }
        len += (size_t)n;
    }
    line[len] = 0;
    return NULL;
}

static void *wait_timed(void *arg) {
    (void)arg;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 1;
    pthread_mutex_lock(&pp_lock);
    int timed_out = 0;
    while (!timed_out) {
        timed_out = pthread_cond_timedwait(&pp_cond, &pp_lock, &deadline) != 0;
    }
    pthread_mutex_unlock(&pp_lock);
    return NULL;
}

static int input_mode(void) {
    static char line[64];
    pthread_t reader, waiter;
    CHECK(pthread_create(&waiter, NULL, wait_timed, NULL) == 0);
    CHECK(pthread_create(&reader, NULL, read_line, line) == 0);
    printf("ready\n");
    CHECK(pthread_join(reader, NULL) == 0);
    CHECK(pthread_join(waiter, NULL) == 0);
    CHECK(strcmp(line, "thread input\n") == 0);
    printf("input: ok\n");
    return 0;
}

static volatile sig_atomic_t alarmed;

static void on_alarm(int signal) {
    (void)signal;
    alarmed = 1;
}

static void *pause_for_alarm(void *arg) {
    (void)arg;
    while (!alarmed) {
        pause();
    }
    printf("alarm: ok\n");
    return NULL;
}

static int alarm_mode(void) {
    struct sigaction action = {.sa_handler = on_alarm};
    CHECK(sigaction(SIGALRM, &action, NULL) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, pause_for_alarm, NULL) == 0);
    sleep_ms(20); // for it to wait
    alarm(1);
    pthread_exit(NULL);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc >= 2 && strcmp(argv[1], "basic") == 0) {
        return basic();
    }
    if (argc >= 2 && strcmp(argv[1], "exit") == 0) {
        return exit_mode();
    }
    if (argc >= 2 && strcmp(argv[1], "detach") == 0) {
        return detach_mode();
    }
    if (argc >= 2 && strcmp(argv[1], "input") == 0) {
        return input_mode();
    }
    if (argc >= 2 && strcmp(argv[1], "alarm") == 0) {
        return alarm_mode();
    }
    fprintf(stderr, "usage: %s basic|exit|detach|input|alarm\n", argv[0]);
    return 2;
}
