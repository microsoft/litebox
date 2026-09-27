// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#ifndef THREADS
#define THREADS 50
#endif

static void *hello(void *argument) {
    int id = (int)(intptr_t)argument;
    printf("Hello from thread %d\n", id);
    return argument;
}

int main(void) {
    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; ++i) {
        if (pthread_create(&threads[i], NULL, hello, (void *)(intptr_t)i)) return 10;
    }
    for (int i = 0; i < THREADS; ++i) {
        void *result;
        if (pthread_join(threads[i], &result) || result != (void *)(intptr_t)i) return 11;
    }
    printf("All threads finished!");
    return 0;
}
