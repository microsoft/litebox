// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Live SVE state survives repeated asynchronous interruptions: signals from the
// main thread interrupt two threads that hold different live states at once.
// Each handler finds its thread's state in a full sve_context and clobbers
// registers, which then return from the frame. LiteBox does not support
// `tgkill` to another thread, so each thread unblocks its own signal and the
// main thread sends that signal to the process. Under LiteBox, each signal also
// interrupts the threads that block it, which resume without a handler. Among
// them is a third thread with a live state that blocks both signals: no
// handler's `rt_sigreturn` replaces its last syscall, the one right before its
// loop head, so it often resumes at the PC that syscall returned to.

#include "helpers.h"

#include <pthread.h>
#include <signal.h>
#include <time.h>

#if defined(__aarch64__)

#include "sve.h"

#define INTERRUPTIONS 20
#define THREADS 2

static const int thread_signals[THREADS] = {SIGUSR1, SIGUSR2};

// Other threads and signal handlers share `loaded` and `interruptions`, so
// every access to them is atomic.
struct live_state {
    struct sve_regs pattern, observed;
    int loaded;
    int interruptions;
    const char *frame_error;
};
_Static_assert(__atomic_always_lock_free(sizeof(int), 0),
               "the signal handlers need lock-free int atomics");

static unsigned long vl;
static struct live_state thread_states[THREADS], bystander;
static __thread struct live_state *current;

static void interrupt_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)info;
    struct live_state *state = current;
    if (state != NULL && __atomic_load_n(&state->loaded, __ATOMIC_ACQUIRE)) {
        struct fpsimd_context *fpsimd;
        struct sve_context *sve;
        sve_find_records(context, &fpsimd, &sve);
        const char *error = fpsimd == NULL || sve == NULL
                                ? "missing fpsimd_context or sve_context"
                                : sve_check_record(sve, &state->pattern, vl);
        if (state->frame_error == NULL) {
            state->frame_error = error;
        }
        __atomic_fetch_add(&state->interruptions, 1, __ATOMIC_RELEASE);
        SVE_CLOBBER_SOME();
    }
}

// Makes a raw getpid syscall, then loads `state->pattern` and spins with it
// live, without syscalls, until enough interruptions arrive or the budget runs
// out, then stores the registers to `state->observed`. The budget must outlast
// `wait_for`'s timeout, so that a stalled handshake fails in the main thread.
// The loop head directly follows the `svc`. Only the first pass, which
// branches to the load on getpid's nonzero result, reaches it without live
// SVE state.
static void spin_with_live_state(struct live_state *state) {
    current = state;
    unsigned long budget = 1UL << 36;
    asm volatile(".arch_extension sve\n\t"
                 "mov x8, #%[getpid]\n\t"
                 "svc #0\n\t"
                 "1:\n\t"
                 "cbnz x0, 3f\n\t"
                 "ldar w9, [%[interruptions]]\n\t"
                 "subs %[budget], %[budget], #1\n\t"
                 "ccmp w9, #%[target], #0, ne\n\t"
                 "b.lt 1b\n\t"
                 "b 2f\n\t"
                 "3:\n\t" SVE_LOAD_ALL
                 "mov x0, #0\n\t"
                 "mov w9, #1\n\t"
                 "stlr w9, [%[loaded]]\n\t"
                 "b 1b\n\t"
                 "2:\n\t" SVE_STORE_ALL
                 : [budget] "+r"(budget)
                 : SVE_LOAD_OPERANDS(&state->pattern), SVE_STORE_OPERANDS(&state->observed),
                   [loaded] "r"(&state->loaded), [interruptions] "r"(&state->interruptions),
                   [target] "i"(INTERRUPTIONS), [getpid] "i"(SYS_getpid)
                 : SVE_CLOBBERS, "x0", "x8", "x9", "cc");
    __atomic_store_n(&state->loaded, 0, __ATOMIC_RELEASE);
}

// Runs thread `index` of `thread_states` and `thread_signals`.
static void *spin_thread(void *index) {
    int i = (int)(intptr_t)index;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, thread_signals[i]);
    TEST_ASSERT(pthread_sigmask(SIG_UNBLOCK, &set, NULL) == 0, "pthread_sigmask failed");
    spin_with_live_state(&thread_states[i]);
    return NULL;
}

// Spins with every thread signal blocked, as inherited from the main thread.
// Under LiteBox, each of them interrupts it without a handler.
static void *spin_bystander(void *unused) {
    (void)unused;
    spin_with_live_state(&bystander);
    return NULL;
}

// Waits up to about ten seconds for `*value` to reach `target`.
static void wait_for(const int *value, int target, const char *msg) {
    const struct timespec pause = {.tv_nsec = 100000};
    for (int i = 0; __atomic_load_n(value, __ATOMIC_ACQUIRE) < target; i++) {
        TEST_ASSERT(i < 100000, msg);
        nanosleep(&pause, NULL);
    }
}

int main(void) {
    if (!sve_available()) {
        printf("sve unavailable\n");
        return 0;
    }
    vl = sve_vl();
    TEST_ASSERT(vl % 16 == 0 && vl <= SVE_MAX_VL, "unexpected vector length");
    printf("sve vl %lu\n", vl);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = interrupt_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < THREADS; i++) {
        TEST_ASSERT(sigaction(thread_signals[i], &sa, NULL) == 0, "sigaction failed");
    }

    sigset_t set;
    sigemptyset(&set);
    for (int i = 0; i < THREADS; i++) {
        sigaddset(&set, thread_signals[i]);
    }
    TEST_ASSERT(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0, "pthread_sigmask failed");
    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; i++) {
        sve_fill_pattern(&thread_states[i].pattern, (uint32_t)i + 1);
        TEST_ASSERT(pthread_create(&threads[i], NULL, spin_thread, (void *)(intptr_t)i) == 0,
                    "pthread_create failed");
    }
    pthread_t bystander_thread;
    sve_fill_pattern(&bystander.pattern, THREADS + 1);
    TEST_ASSERT(pthread_create(&bystander_thread, NULL, spin_bystander, NULL) == 0,
                "pthread_create failed");
    for (int i = 0; i < THREADS; i++) {
        wait_for(&thread_states[i].loaded, 1, "a thread did not load its state");
    }
    wait_for(&bystander.loaded, 1, "the bystander did not load its state");
    for (int round = 1; round <= INTERRUPTIONS; round++) {
        for (int i = 0; i < THREADS; i++) {
            TEST_ASSERT(kill(getpid(), thread_signals[i]) == 0, "kill failed");
            wait_for(&thread_states[i].interruptions, round, "a thread was not interrupted");
        }
    }
    for (int i = 0; i < THREADS; i++) {
        TEST_ASSERT(pthread_join(threads[i], NULL) == 0, "pthread_join failed");
        const struct live_state *state = &thread_states[i];
        TEST_ASSERT(__atomic_load_n(&state->interruptions, __ATOMIC_ACQUIRE) >= INTERRUPTIONS,
                    "too few interruptions");
        TEST_ASSERT(state->frame_error == NULL, state->frame_error);
        const char *error = sve_compare(&state->observed, &state->pattern, vl);
        TEST_ASSERT(error == NULL, error);
    }
    // No handler counts the bystander's interruptions, so this ends its spin.
    __atomic_store_n(&bystander.interruptions, INTERRUPTIONS, __ATOMIC_RELEASE);
    TEST_ASSERT(pthread_join(bystander_thread, NULL) == 0, "pthread_join failed");
    const char *error = sve_compare(&bystander.observed, &bystander.pattern, vl);
    TEST_ASSERT(error == NULL, error);

    printf("sve async ok\n");
    return 0;
}

#else

int main(void) { return 0; }

#endif
