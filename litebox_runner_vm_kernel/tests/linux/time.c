// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The wall clock's interfaces agree and it advances with the monotonic clock.
// See time.json.

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

static long long ns(clockid_t clock) {
    struct timespec ts;
    clock_gettime(clock, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(void) {
    time_t now = time(NULL);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long realtime = ns(CLOCK_REALTIME);
    // Read in order, so each is `now` or up to a second later.
    long long tv_after = tv.tv_sec - now;
    long long realtime_after = realtime / 1000000000LL - now;
    int agree = 0 <= tv_after && tv_after <= 1 && 0 <= realtime_after && realtime_after <= 1;
    printf("agree: %d\n", agree);

    long long real = ns(CLOCK_REALTIME);
    long long mono = ns(CLOCK_MONOTONIC);
    struct timespec twenty_ms = {0, 20 * 1000 * 1000};
    nanosleep(&twenty_ms, NULL);
    long long real_elapsed = ns(CLOCK_REALTIME) - real;
    long long mono_elapsed = ns(CLOCK_MONOTONIC) - mono;
    long long skew = real_elapsed - mono_elapsed;
    // The same clock underneath, so only the reads' spacing differs.
    int advances = real_elapsed >= 20000000 && skew < 5000000 && skew > -5000000;
    printf("advances: %d\n", advances);
    return agree && advances ? 0 : 1;
}
