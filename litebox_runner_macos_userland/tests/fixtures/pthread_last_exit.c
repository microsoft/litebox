// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static char buffer[4096];
static atomic_int ready;
static atomic_int remaining;
static pthread_key_t key;

static void thread_cleanup(void *value) {
    (void)value;
    atomic_fetch_sub(&remaining, 1);
}

static void cleanup(void) {
    // Cleanup still needs the exiting thread's TSD, even after a joiner has
    // reclaimed its pthread object from libpthread's point of view.
    errno = E2BIG;
    if (close(-1) != -1 || errno != EBADF) _Exit(22);
    if (atomic_load(&remaining)) _Exit(20);
    if (write(1, "ATEXIT\n", 7) != 7) _Exit(21);
}

static void *worker(void *unused) {
    (void)unused;
    if (pthread_setspecific(key, &key)) _Exit(14);
    while (!atomic_load(&ready)) { }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    int join = argv[1][0] == 'j';
    int count = join ? 1 : atoi(argv[1]);
    if (count < 0 || count > 50) return 11;
    if (setvbuf(stdout, buffer, _IOFBF, sizeof(buffer)) || atexit(cleanup)) return 12;
    printf("STDOUT_BUFFERED");
    if (pthread_key_create(&key, thread_cleanup) || pthread_setspecific(key, &key)) return 15;
    atomic_store(&remaining, count + 1);
    pthread_t thread;
    for (int i = 0; i < count; ++i) {
        if (pthread_create(&thread, NULL, worker, NULL)) return 13;
    }
    atomic_store(&ready, 1);
    if (join && pthread_join(thread, NULL)) return 16;
    pthread_exit(NULL);
}
