// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Timer files: blocking reads, periodic expirations, absolute deadlines, the
// previous setting, disarming, and readiness through poll and epoll, each no
// earlier than the timer; and a nonblocking epoll sees timers that expired
// while the program made no syscalls, even more of them at once than the
// notification ring holds. See timerfd.json.

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
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

// Returns whether timerfd_settime succeeded.
static int arm(int fd, long value_ms, long interval_ms) {
    struct itimerspec spec = {
        .it_interval = {interval_ms / 1000, interval_ms % 1000 * 1000000},
        .it_value = {value_ms / 1000, value_ms % 1000 * 1000000},
    };
    return timerfd_settime(fd, 0, &spec, NULL) == 0;
}

static int read_expirations(int fd, uint64_t *expirations) {
    return read(fd, expirations, sizeof(*expirations)) == sizeof(*expirations);
}

// More than the notification ring's 64 slots.
#define MANY 70

int main(void) {
    int ok = 1;
    calibrate();
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    uint64_t expirations = 0;

    long long start = now_us();
    int one_shot = arm(fd, 20, 0) && read_expirations(fd, &expirations) && expirations == 1 &&
                   now_us() - start >= 20000;
    printf("one-shot: %d\n", one_shot);
    ok &= one_shot;

    start = now_us();
    int periodic = arm(fd, 10, 10);
    struct timespec thirty_five_ms = {0, 35 * 1000 * 1000};
    nanosleep(&thirty_five_ms, NULL);
    periodic &= read_expirations(fd, &expirations);
    long long elapsed = now_us() - start;
    // At least three; at most one per 10 ms that actually passed.
    periodic &= expirations >= 3 && (long long)expirations <= elapsed / 10000;
    printf("periodic: %d\n", periodic);
    ok &= periodic;

    // The previous setting, then disarmed: nothing more to read.
    struct itimerspec off = {0}, old;
    int disarmed = timerfd_settime(fd, 0, &off, &old) == 0 && old.it_interval.tv_nsec == 10000000 &&
                   old.it_value.tv_sec == 0 && old.it_value.tv_nsec <= 10000000;
    int nonblocking_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    disarmed &= arm(nonblocking_fd, 5, 0) && arm(nonblocking_fd, 0, 0);
    spin_us(10000);
    disarmed &= read(nonblocking_fd, &expirations, sizeof(expirations)) == -1 && errno == EAGAIN;
    printf("disarm: %d\n", disarmed);
    ok &= disarmed;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    start = now_us();
    struct itimerspec absolute = {.it_value = {now.tv_sec, now.tv_nsec + 20000000}};
    if (absolute.it_value.tv_nsec >= 1000000000) {
        absolute.it_value.tv_sec++;
        absolute.it_value.tv_nsec -= 1000000000;
    }
    int abstime = timerfd_settime(fd, TFD_TIMER_ABSTIME, &absolute, NULL) == 0 &&
                  read_expirations(fd, &expirations) && expirations == 1 &&
                  now_us() - start >= 19000;
    printf("absolute: %d\n", abstime);
    ok &= abstime;

    start = now_us();
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int polled = arm(fd, 15, 0) && poll(&pfd, 1, 1000) == 1 && (pfd.revents & POLLIN) &&
                 now_us() - start >= 15000 && read_expirations(fd, &expirations);
    printf("poll: %d\n", polled);
    ok &= polled;

    int ep = epoll_create1(0);
    struct epoll_event event = {.events = EPOLLIN, .data.fd = fd};
    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event);
    start = now_us();
    struct epoll_event ready[MANY];
    int epolled = arm(fd, 15, 0) && epoll_wait(ep, ready, 1, 1000) == 1 &&
                  ready[0].data.fd == fd && now_us() - start >= 15000;
    printf("epoll: %d\n", epolled);
    ok &= epolled;

    // A timer that was never ready while registered, so only its expiry's
    // notification can put it on the ready list.
    int fresh = timerfd_create(CLOCK_MONOTONIC, 0);
    int fresh_ep = epoll_create1(0);
    struct epoll_event fresh_event = {.events = EPOLLIN, .data.fd = fresh};
    epoll_ctl(fresh_ep, EPOLL_CTL_ADD, fresh, &fresh_event);
    int nonblocking = arm(fresh, 20, 0);
    spin_us(60000);
    nonblocking &= epoll_wait(fresh_ep, ready, 1, 0) == 1 && ready[0].data.fd == fresh;
    printf("epoll nonblocking: %d\n", nonblocking);
    ok &= nonblocking;

    // As many at the same deadline, more than the notification ring holds.
    int many_ep = epoll_create1(0);
    int many_fds[MANY];
    for (int i = 0; i < MANY; i++) {
        many_fds[i] = timerfd_create(CLOCK_MONOTONIC, 0);
        struct epoll_event many_event = {.events = EPOLLIN, .data.fd = many_fds[i]};
        epoll_ctl(many_ep, EPOLL_CTL_ADD, many_fds[i], &many_event);
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    absolute.it_value.tv_sec = now.tv_sec + 1;
    absolute.it_value.tv_nsec = now.tv_nsec;
    int many = 1;
    for (int i = 0; i < MANY; i++) {
        many &= timerfd_settime(many_fds[i], TFD_TIMER_ABSTIME, &absolute, NULL) == 0;
    }
    spin_us(1100000);
    int count = epoll_wait(many_ep, ready, MANY, 0);
    many &= count == MANY;
    printf("epoll many: %d (%d)\n", many, count);
    ok &= many;
    return ok ? 0 : 1;
}
