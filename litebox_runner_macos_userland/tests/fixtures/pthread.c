// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <pthread.h>
#include <os/lock.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NUM_THREADS 50

static atomic_int ready;
static os_unfair_lock release_threads = OS_UNFAIR_LOCK_INIT;
static atomic_int destructed;
static pthread_key_t key;
static pthread_t identities[NUM_THREADS];

static void destroy_value(void *value) {
    if (value) atomic_fetch_add(&destructed, 1);
}

static void *thread_func(void *arg) {
    int id = *(int *)arg;
    identities[id] = pthread_self();
    if (pthread_setspecific(key, (void *)(uintptr_t)(id + 1))) return NULL;
    errno = E2BIG;
    atomic_fetch_add_explicit(&ready, 1, memory_order_release);
    os_unfair_lock_lock(&release_threads);
    os_unfair_lock_unlock(&release_threads);
    (void)getpid();
    if (errno != E2BIG || pthread_getspecific(key) != (void *)(uintptr_t)(id + 1)) return NULL;
    if (printf("Hello from thread %d\n", id) < 0) return NULL;
    return (void *)(uintptr_t)(id + 1);
}

static int run_round(void) {
    atomic_store(&ready, 0);
    // Waiters must be woken by the executing main thread, not its parked TSD donor.
    os_unfair_lock_lock(&release_threads);
    atomic_store(&destructed, 0);
    pthread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];
    if (pthread_key_create(&key, destroy_value)) return 1;
    for (int i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        int error = pthread_create(&threads[i], NULL, thread_func, &ids[i]);
        if (error) return 10 + error;
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) != NUM_THREADS) { }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (!pthread_equal(threads[i], identities[i])) return 2;
        for (int j = 0; j < i; j++) if (pthread_equal(identities[i], identities[j])) return 3;
    }
    os_unfair_lock_unlock(&release_threads);
    for (int i = 0; i < NUM_THREADS; i++) {
        void *value;
        int error = pthread_join(threads[i], &value);
        if (error) return 20 + error;
        if ((uintptr_t)value != (uintptr_t)(i + 1)) return 4;
    }
    if (atomic_load(&destructed) != NUM_THREADS) return 5;
    if (pthread_key_delete(key)) return 6;
    puts("All threads finished!");
    return 0;
}

// Usually outlives the main thread; the process exits with its last thread.
// It cannot join the main thread, whose pthread is still the runner's donor.
static void *last_thread(void *arg) {
    (void)arg;
    usleep(10000);
    puts("Main thread exited");
    return NULL;
}

static void *unused_worker(void *arg) { return arg; }

// Custom stacks need Mach semaphores to join, so creation must fail up front.
static int custom_stack_is_rejected(void) {
    static _Alignas(16384) char stack[512 * 1024];
    pthread_attr_t attr;
    pthread_t thread;
    if (pthread_attr_init(&attr) || pthread_attr_setstack(&attr, stack, sizeof(stack))) return 10;
    int error = pthread_create(&thread, &attr, unused_worker, NULL);
    pthread_attr_destroy(&attr);
    return error ? 0 : 11;
}

int main(void) {
    for (int round = 0; round < 3; round++) {
        int error = run_round();
        if (error) return error;
    }
    int error = custom_stack_is_rejected();
    if (error) return error;
    pthread_t thread;
    if (pthread_create(&thread, NULL, last_thread, NULL)) return 9;
    pthread_exit(NULL);
}
