// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void *child_thread_func(void *arg) {
    (void)arg;
    printf("Hello from child thread.\n");
    return NULL;
}

int main(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, child_thread_func, NULL) != 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }
    printf("Hello from main thread.\n");
    if (pthread_join(tid, NULL) != 0) {
        perror("pthread_join");
        return EXIT_FAILURE;
    }
    return 0;
}
