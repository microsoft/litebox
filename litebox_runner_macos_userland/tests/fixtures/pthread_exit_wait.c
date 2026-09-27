// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <mach/mach_time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

extern int __ulock_wait(uint32_t, void *, uint64_t, uint32_t);
extern int __ulock_wait2(uint32_t, void *, uint64_t, uint64_t, uint64_t);

static pthread_mutex_t mutex;
static atomic_int ready;
static atomic_int start;
static _Atomic uint32_t word;

// This fixture uses the same bounded macOS libpthread ABI as the bridge.
// For an aligned fair-share mutex, m_seq starts at byte 32; each lock attempt
// increments lgen by 0x100. Observe actual slow-path entry, not elapsed time.
// The kernel-wait/interrupt ordering is tested separately in the shim.
typedef uint32_t mutex_word __attribute__((may_alias));
static uint32_t lock_generation(void) {
    const mutex_word *sequence = (const mutex_word *)((const char *)&mutex + 32);
    return __atomic_load_n(sequence, __ATOMIC_ACQUIRE) & UINT32_C(0xffffff00);
}
_Static_assert(_Alignof(pthread_mutex_t) >= 8 && sizeof(pthread_mutex_t) >= 40,
               "unsupported mutex layout");

static void *exiter(void *argument) {
    const char *mode = argument;
    if (mode[0] == 'm') {
        if (pthread_mutex_lock(&mutex)) _Exit(20);
        if (lock_generation() != 0x100) _Exit(22);
    }
    atomic_store(&ready, 1);
    while (!atomic_load(&start)) { }
    if (mode[0] == 'm') {
        // Only main can advance this generation while we retain the lock.
        while (lock_generation() == 0x100) { }
        if (lock_generation() != 0x200) _Exit(23);
        if (write(1, "MUTEX_WAIT_PATH\n", 16) != 16) _Exit(24);
    } else {
        mach_timebase_info_data_t clock;
        if (mach_timebase_info(&clock)) _Exit(21);
        mach_wait_until(mach_absolute_time() + UINT64_C(20000000) * clock.denom / clock.numer);
    }
    // Do not unlock: main must leave its native wait because the process exits.
    exit(5);
}

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) ||
        pthread_mutexattr_setpolicy_np(&attr, PTHREAD_MUTEX_POLICY_FAIRSHARE_NP) ||
        pthread_mutex_init(&mutex, &attr)) return 11;
    pthread_mutexattr_destroy(&attr);
    pthread_t worker;
    if (pthread_create(&worker, NULL, exiter, argv[1])) return 12;
    while (!atomic_load(&ready)) { }
    atomic_store(&start, 1);
    switch (argv[1][0]) {
    case 'm': pthread_mutex_lock(&mutex); break;
    case '1': __ulock_wait(1, &word, 0, 0); break; // UL_COMPARE_AND_WAIT
    case '2': __ulock_wait2(1, &word, 0, 0, 0); break;
    default: return 13;
    }
    return 14; // None of these waits should return to guest code.
}
