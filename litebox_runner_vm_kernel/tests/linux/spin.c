// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Usage: spin <ms> <min_gaps>. Spins for <ms> milliseconds, counting gaps of
// at least 5 ms in its view of the monotonic clock: times another process had
// the CPU. Exits 0 if it saw at least <min_gaps>. See sched.json.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

int main(int argc, char *argv[]) {
    long long duration = (argc > 1 ? atoll(argv[1]) : 300) * 1000000LL;
    long min_gaps = argc > 2 ? atol(argv[2]) : 0;
    long gaps = 0;
    long long start = now_ns(), last = start, now;
    while ((now = now_ns()) - start < duration) {
        if (now - last >= 5000000LL) {
            gaps++;
        }
        last = now;
    }
    printf("spin: %ld gaps in %lld ms\n", gaps, duration / 1000000LL);
    return gaps >= min_gaps ? 0 : 1;
}
