// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// For the kernel's scheduler, with several programs at once. The first
// argument picks a mode:
// - "spin MS MIN_GAP_MS MAX_GAP_MS [DELAY_MS]": busy-waits for MS milliseconds, with no
//   syscalls but clock reads (which the runner serves without the kernel),
//   computing in floating point all along, with a GS base set by `wrgsbase`
//   (not a syscall). Fails unless the longest gap between consecutive clock
//   reads, while other programs ran, is in [MIN_GAP_MS, MAX_GAP_MS], and
//   unless the computation, the rounding mode, and the GS base survived the
//   switches. With DELAY_MS, sleeps that long first.
// - "sleep MS COUNT": sleeps COUNT times for MS milliseconds; fails if one
//   is too short.
// - "calls COUNT MAX_MS": makes COUNT broker calls (one-byte reads of a
//   file); fails if they took longer than MAX_MS, e.g., if each one gave up
//   the CPU to other programs.
// - "input MAX_MS": prints `ready`, for the host to send console input (see
//   sched.input.txt), then waits for it with no timeout; fails if it took
//   longer than MAX_MS, e.g., while other programs ran.
// See sched.json.

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
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

static int calls_mode(int count, long long max_ms) {
    int fd = open("/sched", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "calls: open failed\n");
        return 1;
    }
    char byte;
    long long start = now_us();
    for (int i = 0; i < count; i++) {
        if (pread(fd, &byte, 1, i) != 1) {
            fprintf(stderr, "calls: read %d failed\n", i);
            return 1;
        }
    }
    long long took = now_us() - start;
    close(fd);
    if (took > max_ms * 1000) {
        fprintf(stderr, "calls: %d took %lld us\n", count, took);
        return 1;
    }
    return 0;
}

static int input_mode(long long max_ms) {
    if (write(1, "ready\n", 6) != 6) {
        return 1;
    }
    long long start = now_us();
    struct pollfd pfd = {.fd = 0, .events = POLLIN};
    if (poll(&pfd, 1, -1) != 1 || !(pfd.revents & POLLIN)) {
        fprintf(stderr, "input: poll failed\n");
        return 1;
    }
    long long waited = now_us() - start;
    if (waited > max_ms * 1000) {
        fprintf(stderr, "input: waited %lld us\n", waited);
        return 1;
    }
    return 0;
}

static int sleep_ms(long long ms) {
    struct timespec duration = {ms / 1000, (ms % 1000) * 1000000};
    return nanosleep(&duration, NULL);
}

static int sleep_mode(long long ms, int count) {
    for (int i = 0; i < count; i++) {
        long long start = now_us();
        if (sleep_ms(ms) != 0 || now_us() - start < ms * 1000) {
            fprintf(stderr, "sleep: %d too short\n", i);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if ((argc == 5 || argc == 6) && strcmp(argv[1], "spin") == 0) {
        if (argc == 6) {
            sleep_ms(atoll(argv[5]));
        }
        return spin_mode(atoll(argv[2]), atoll(argv[3]), atoll(argv[4]));
    }
    if (argc == 4 && strcmp(argv[1], "sleep") == 0) {
        return sleep_mode(atoll(argv[2]), atoi(argv[3]));
    }
    if (argc == 4 && strcmp(argv[1], "calls") == 0) {
        return calls_mode(atoi(argv[2]), atoll(argv[3]));
    }
    if (argc == 3 && strcmp(argv[1], "input") == 0) {
        return input_mode(atoll(argv[2]));
    }
    fprintf(stderr, "usage: sched spin MS MIN_GAP_MS MAX_GAP_MS [DELAY_MS] | sleep MS COUNT | calls COUNT MAX_MS | input MAX_MS\n");
    return 2;
}
