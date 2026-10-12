// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The wall clock: its interfaces agree, it is a plausible date (from
// kvm-clock), or else the boot's time since the Unix epoch, and it advances
// with the monotonic clock. See time.json.

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
    // Read in order, so each is `now` or up to a second later; and after
    // 2024-01-01, or, without kvm-clock (counted from the epoch at the clock's
    // origin), before 2000.
    long long tv_after = tv.tv_sec - now;
    long long realtime_after = realtime / 1000000000LL - now;
    int agree = 0 <= tv_after && tv_after <= 1 && 0 <= realtime_after && realtime_after <= 1;
    int plausible = now > 1704067200 || now < 946684800;
    printf("agree: %d\nplausible: %d\n", agree, plausible);

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
    return agree && plausible && advances ? 0 : 1;
}
