// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Waits with timeouts, which nothing else ends, so each lasts at least its
// timeout on the monotonic clock, and not much longer. See sleep.json.

#include <errno.h>
#include <linux/futex.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

// Slack for the late side (e.g., a slow emulator), far below a missed
// deadline's.
#define MAX_OVERSHOOT_US 500000

static int check(const char *what, long long start, long long min_us) {
    long long elapsed = now_us() - start;
    const char *result = elapsed < min_us                      ? "too short"
                         : elapsed > min_us + MAX_OVERSHOOT_US ? "too long"
                                                               : "ok";
    printf("%s: %s\n", what, result);
    return result[0] == 'o';
}

int main(void) {
    int ok = 1;
    long long start = now_us();
    struct timespec ten_ms = {0, 10 * 1000 * 1000};
    ok &= nanosleep(&ten_ms, NULL) == 0 && check("nanosleep", start, 10000);

    start = now_us();
    ok &= usleep(5000) == 0 && check("usleep", start, 5000);

    int word = 0;
    start = now_us();
    long r = syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, &ten_ms, NULL, 0);
    ok &= r == -1 && errno == ETIMEDOUT && check("futex", start, 10000);
    return ok ? 0 : 1;
}
