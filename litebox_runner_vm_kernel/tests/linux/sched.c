// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// For the kernel's scheduler, with several programs at once. The first
// argument picks a mode:
// - "spin MS MIN_GAP_MS MAX_GAP_MS": busy-waits for MS milliseconds, with no
//   syscalls but clock reads (which the runner serves without the kernel),
//   computing in floating point all along, with a GS base set by `wrgsbase`
//   (not a syscall). Fails unless the longest gap between consecutive clock
//   reads, while other programs ran, is in [MIN_GAP_MS, MAX_GAP_MS], and
//   unless the computation, the rounding mode, and the GS base survived the
//   switches.
// - "sleep MS COUNT": sleeps COUNT times for MS milliseconds; fails if one
//   is too short.
// See sched.json.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <xmmintrin.h>

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

// One step of a computation that any lost x87/SSE state would change.
static double step(double x) {
    return x * 1.000000119 + 0.5;
}

static int spin_mode(long long ms, long long min_gap_ms, long long max_gap_ms) {
    static char gs_area[64];
    unsigned long long gs_expected = (unsigned long long)gs_area;
    __asm__ volatile("wrgsbase %0" : : "r"(gs_expected));
    // Rounds up: not the default, so a switch that dropped MXCSR would show.
    unsigned int mxcsr = _mm_getcsr();
    _mm_setcsr((mxcsr & ~_MM_ROUND_MASK) | _MM_ROUND_UP);
    long long start = now_us();
    long long last = start;
    long long max_gap = 0;
    long long steps = 0;
    double x = 1.0;
    while (last - start < ms * 1000) {
        x = step(x);
        steps++;
        long long now = now_us();
        if (now - last > max_gap) {
            max_gap = now - last;
        }
        last = now;
    }
    int rounding = (_mm_getcsr() & _MM_ROUND_MASK) == _MM_ROUND_UP;
    unsigned long long gs;
    __asm__ volatile("rdgsbase %0" : "=r"(gs));
    __asm__ volatile("wrgsbase %0" : : "r"(0ULL));
    double expected = 1.0;
    for (long long i = 0; i < steps; i++) {
        expected = step(expected);
    }
    _mm_setcsr(mxcsr);
    int gap = max_gap >= min_gap_ms * 1000 && max_gap <= max_gap_ms * 1000;
    if (!gap || !rounding || x != expected || gs != gs_expected) {
        fprintf(stderr, "spin: max gap %lld us, rounding %d, computation %d, gs %d\n", max_gap,
                rounding, x == expected, gs == gs_expected);
        return 1;
    }
    return 0;
}

static int sleep_mode(long long ms, int count) {
    struct timespec duration = {ms / 1000, (ms % 1000) * 1000000};
    for (int i = 0; i < count; i++) {
        long long start = now_us();
        if (nanosleep(&duration, NULL) != 0 || now_us() - start < ms * 1000) {
            fprintf(stderr, "sleep: %d too short\n", i);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 5 && strcmp(argv[1], "spin") == 0) {
        return spin_mode(atoll(argv[2]), atoll(argv[3]), atoll(argv[4]));
    }
    if (argc == 4 && strcmp(argv[1], "sleep") == 0) {
        return sleep_mode(atoll(argv[2]), atoi(argv[3]));
    }
    fprintf(stderr, "usage: sched spin MS MIN_GAP_MS MAX_GAP_MS | sleep MS COUNT\n");
    return 2;
}
