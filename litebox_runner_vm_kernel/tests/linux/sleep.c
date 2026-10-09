// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Usage: sleep <ms>. Sleeps <ms> milliseconds; exits 0 if that took at least
// <ms> and less than <ms> + 500. See sched.json.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    long ms = argc > 1 ? atol(argv[1]) : 100;
    struct timespec request = {ms / 1000, (ms % 1000) * 1000000L}, start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (nanosleep(&request, NULL) != 0) {
        perror("nanosleep");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    printf("sleep: %ld ms for %ld ms\n", elapsed, ms);
    return elapsed >= ms && elapsed < ms + 500 ? 0 : 1;
}
