// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <mach/mach_time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

extern int __ulock_wait(uint32_t, void *, uint64_t, uint32_t);
extern int __ulock_wait2(uint32_t, void *, uint64_t, uint64_t, uint64_t);

static pthread_mutex_t mutex;
static atomic_int ready;
static atomic_int start;
static _Atomic uint32_t word;

static void *exiter(void *argument) {
    const char *mode = argument;
    if (mode[0] == 'm' && pthread_mutex_lock(&mutex)) _Exit(20);
    atomic_store(&ready, 1);
    while (!atomic_load(&start)) { }
    mach_timebase_info_data_t clock;
    if (mach_timebase_info(&clock)) _Exit(21);
    mach_wait_until(mach_absolute_time() + UINT64_C(20000000) * clock.denom / clock.numer);
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
