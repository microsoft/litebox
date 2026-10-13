// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// SIGALRM from alarm and setitimer: it ends pause(), runs the handler, and
// arrives during a true busy loop with no syscalls at all (real preemption,
// not just at the program's next syscall). The first argument picks a mode:
// - "default": with no handler, the program dies by the signal;
// - "sleep": the signal ends a longer timed wait (nanosleep) early;
// - "stress": timers expiring at varied points around (reflected) syscalls,
//   e.g., while the runner takes a reflected syscall's upcall, are never
//   lost and never kill the program.
// See alarm.json.

#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

static volatile sig_atomic_t fired;

static void on_alarm(int signal) {
    (void)signal;
    fired = 1;
}

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static void arm_ms(long ms) {
    struct itimerval timer = {.it_value = {0, ms * 1000}};
    setitimer(ITIMER_REAL, &timer, NULL);
}

static double ticks_per_us;

// Calibrates `spin_us` against the monotonic clock.
static void calibrate(void) {
    unsigned long long ticks = __rdtsc();
    long long start = now_us();
    struct timespec five_ms = {0, 5 * 1000 * 1000};
    nanosleep(&five_ms, NULL);
    ticks_per_us = (double)(__rdtsc() - ticks) / (double)(now_us() - start);
}

// Busy-waits without syscalls.
static void spin_us(long long us) {
    unsigned long long end = __rdtsc() + (unsigned long long)(us * ticks_per_us);
    while (__rdtsc() < end) {
    }
}

static void arm_us(long us) {
    struct itimerval timer = {.it_value = {us / 1000000, us % 1000000}};
    setitimer(ITIMER_REAL, &timer, NULL);
}

// Busy-waits without syscalls until the handler runs or `us` pass; returns
// whether it ran.
static int spin_until_fired(long long us) {
    unsigned long long end = __rdtsc() + (unsigned long long)(us * ticks_per_us);
    while (!fired && __rdtsc() < end) {
    }
    return fired;
}

static int sleep_mode(void) {
    long long start = now_us();
    arm_ms(30);
    struct timespec two_s = {2, 0};
    int result = nanosleep(&two_s, NULL);
    long long elapsed = now_us() - start;
    int ok = result == -1 && errno == EINTR && fired && elapsed >= 30000 && elapsed < 1000000;
    printf("sleep: %d\n", ok);
    return ok ? 0 : 1;
}

typedef long (*raw_syscall_fn)(long nr, long a, long b, long c);

static int stress_mode(void) {
    // mov rax, rdi; mov rdi, rsi; mov rsi, rdx; mov rdx, rcx; syscall; ret:
    // in anonymous memory, so the kernel reflects it (see reflect.c).
    static const unsigned char stub[] = {
        0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6,
        0x48, 0x89, 0xca, 0x0f, 0x05, 0xc3,
    };
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        return 1;
    }
    memcpy(page, stub, sizeof(stub));
    mprotect(page, 4096, PROT_READ | PROT_EXEC);
    raw_syscall_fn raw_syscall = (raw_syscall_fn)page;

    // Timers expiring during runs of syscalls, then spinning with none.
    int missed = 0;
    for (int i = 0; i < 2000; i++) {
        fired = 0;
        arm_us(1 + i % 200);
        for (int j = 0; j < 8 && !fired; j++) {
            if (i % 2 == 0) {
                raw_syscall(SYS_getpid, 0, 0, 0);
            } else {
                getppid();
            }
        }
        if (!spin_until_fired(100000)) {
            missed++;
        }
    }
    printf("stress missed: %d\n", missed);
    return missed == 0 ? 0 : 1;
}

int main(int argc, char *argv[]) {
    const char *mode = argc > 1 ? argv[1] : "";
    if (strcmp(mode, "default") == 0) {
        alarm(1);
        for (;;) {
        }
    }
    struct sigaction action = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &action, NULL);
    calibrate();
    if (strcmp(mode, "sleep") == 0) {
        return sleep_mode();
    }
    if (strcmp(mode, "stress") == 0) {
        return stress_mode();
    }

    long long start = now_us();
    arm_ms(30);
    int paused = pause() == -1 && fired && now_us() - start >= 30000;
    printf("pause: %d\n", paused);

    fired = 0;
    start = now_us();
    arm_ms(30);
    spin_us(200000); // 200ms busy loop, no syscalls, for a 30ms alarm
    int busy = fired && now_us() - start >= 30000;
    printf("busy loop: %d\n", busy);

    fired = 0;
    alarm(5);
    unsigned int remaining = alarm(0);
    int cancelled = remaining >= 4 && remaining <= 5 && !fired;
    printf("alarm: %d\n", cancelled);
    return paused && busy && cancelled ? 0 : 1;
}
