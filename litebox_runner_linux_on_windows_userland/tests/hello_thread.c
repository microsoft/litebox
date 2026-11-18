// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *child_thread_func(void *arg) {
    (void)arg;
    printf("Hello from child thread.\n");
    return NULL;
}

int main(void) {
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, child_thread_func, NULL);
    if (rc != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(rc));
        return EXIT_FAILURE;
    }
    printf("Hello from main thread.\n");
    rc = pthread_join(tid, NULL);
    if (rc != 0) {
        fprintf(stderr, "pthread_join: %s\n", strerror(rc));
        return EXIT_FAILURE;
    }
    return 0;
}
