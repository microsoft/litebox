// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: timerfd_create/timerfd_settime/timerfd_gettime, reads, epoll
// readiness, and argument validation. Timing checks only use lower bounds on
// elapsed time or upper bounds on remaining time so that slow hosts cannot
// make them fail.

#include "helpers.h"

#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <time.h>

#define MS 1000000L

static struct itimerspec spec(long value_ns, long interval_ns) {
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = value_ns / 1000000000L;
    its.it_value.tv_nsec = value_ns % 1000000000L;
    its.it_interval.tv_sec = interval_ns / 1000000000L;
    its.it_interval.tv_nsec = interval_ns % 1000000000L;
    return its;
}

static long ns(const struct timespec *ts) {
    return (long)ts->tv_sec * 1000000000L + ts->tv_nsec;
}

static struct itimerspec absolute(clockid_t clock, long delay_ns) {
    struct timespec now;
    TEST_ASSERT(clock_gettime(clock, &now) == 0, "clock_gettime");
    return spec(ns(&now) + delay_ns, 0);
}

static long remaining_ns(int fd) {
    struct itimerspec its;
    TEST_ASSERT(timerfd_gettime(fd, &its) == 0, "timerfd_gettime");
    return ns(&its.it_value);
}

static uint64_t read_expirations(int fd) {
    uint64_t expirations = 0;
    TEST_ASSERT(read(fd, &expirations, sizeof(expirations)) == sizeof(expirations),
                "read expirations");
    return expirations;
}

static void expect_errno(int result, int expected, const char *msg) {
    TEST_ASSERT(result == -1 && errno == expected, msg);
}

static void test_one_shot(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    TEST_ASSERT(fd >= 0, "timerfd_create");
    int status = fcntl(fd, F_GETFL);
    TEST_ASSERT((status & O_ACCMODE) == O_RDWR && (status & O_NONBLOCK), "status flags");

    uint64_t expirations;
    expect_errno(read(fd, &expirations, sizeof(expirations)), EAGAIN, "disarmed read");
    TEST_ASSERT(remaining_ns(fd) == 0, "disarmed gettime");

    struct itimerspec armed = spec(100 * MS, 0);
    struct itimerspec old;
    memset(&old, 0xff, sizeof(old));
    TEST_ASSERT(timerfd_settime(fd, 0, &armed, &old) == 0, "arm");
    TEST_ASSERT(ns(&old.it_value) == 0 && ns(&old.it_interval) == 0, "old disarmed");
    long remaining = remaining_ns(fd);
    TEST_ASSERT(remaining >= 0 && remaining <= 100 * MS, "armed gettime");

    TEST_ASSERT(fcntl(fd, F_SETFL, 0) == 0, "clear O_NONBLOCK");
    TEST_ASSERT(read_expirations(fd) == 1, "one-shot expires once");
    TEST_ASSERT(remaining_ns(fd) == 0, "one-shot disarms");
    TEST_ASSERT(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "set O_NONBLOCK");
    expect_errno(read(fd, &expirations, sizeof(expirations)), EAGAIN, "consumed");
    TEST_ASSERT(close(fd) == 0, "close");
}

static void test_periodic(void) {
    int fd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK | TFD_CLOEXEC);
    TEST_ASSERT(fd >= 0, "timerfd_create");
    TEST_ASSERT(fcntl(fd, F_GETFD) == FD_CLOEXEC, "TFD_CLOEXEC");

    struct itimerspec armed = spec(10 * MS, 10 * MS);
    TEST_ASSERT(timerfd_settime(fd, 0, &armed, NULL) == 0, "arm periodic");
    usleep(55 * 1000);
    TEST_ASSERT(read_expirations(fd) >= 5, "missed periods are counted");

    struct itimerspec its;
    TEST_ASSERT(timerfd_gettime(fd, &its) == 0, "gettime periodic");
    TEST_ASSERT(ns(&its.it_interval) == 10 * MS, "interval preserved");
    TEST_ASSERT(ns(&its.it_value) > 0 && ns(&its.it_value) <= 10 * MS, "next period");

    struct itimerspec disarm = spec(0, 0);
    struct itimerspec old;
    TEST_ASSERT(timerfd_settime(fd, 0, &disarm, &old) == 0, "disarm");
    TEST_ASSERT(ns(&old.it_interval) == 10 * MS, "old interval");
    TEST_ASSERT(remaining_ns(fd) == 0, "disarmed");
    TEST_ASSERT(close(fd) == 0, "close");
}

static void test_absolute(clockid_t clock) {
    int fd = timerfd_create(clock, 0);
    TEST_ASSERT(fd >= 0, "timerfd_create");

    struct itimerspec armed = absolute(clock, 100 * MS);
    TEST_ASSERT(timerfd_settime(fd, TFD_TIMER_ABSTIME, &armed, NULL) == 0, "arm absolute");
    long remaining = remaining_ns(fd);
    TEST_ASSERT(remaining >= 0 && remaining <= 100 * MS, "absolute time uses the clock");
    TEST_ASSERT(read_expirations(fd) == 1, "absolute expires");

    struct itimerspec past = spec(1, 0);
    TEST_ASSERT(timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, NULL) == 0, "arm past");
    TEST_ASSERT(read_expirations(fd) == 1, "past time expires immediately");
    TEST_ASSERT(close(fd) == 0, "close");
}

static void test_epoll(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    TEST_ASSERT(fd >= 0, "timerfd_create");
    int epfd = epoll_create1(0);
    TEST_ASSERT(epfd >= 0, "epoll_create1");
    struct epoll_event event = {.events = EPOLLIN, .data.fd = fd};
    TEST_ASSERT(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) == 0, "epoll_ctl");

    struct epoll_event ready;
    TEST_ASSERT(epoll_wait(epfd, &ready, 1, 0) == 0, "disarmed not ready");
    struct itimerspec armed = spec(10 * MS, 0);
    TEST_ASSERT(timerfd_settime(fd, 0, &armed, NULL) == 0, "arm");
    TEST_ASSERT(epoll_wait(epfd, &ready, 1, 10000) == 1, "expiration wakes epoll");
    TEST_ASSERT(ready.data.fd == fd && (ready.events & EPOLLIN), "EPOLLIN");
    TEST_ASSERT(read_expirations(fd) == 1, "read after epoll");
    TEST_ASSERT(epoll_wait(epfd, &ready, 1, 0) == 0, "read clears readiness");

    TEST_ASSERT(close(epfd) == 0, "close epoll");
    TEST_ASSERT(close(fd) == 0, "close");
}

static void test_invalid_arguments(void) {
    expect_errno(timerfd_create(CLOCK_PROCESS_CPUTIME_ID, 0), EINVAL, "unsupported clock");
    expect_errno(timerfd_create(CLOCK_MONOTONIC, 1), EINVAL, "unknown create flag");

    int fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    TEST_ASSERT(fd >= 0, "timerfd_create");
    struct itimerspec armed = spec(10 * MS, 0);
    // LiteBox cannot observe wall-clock changes, so unlike Linux it rejects this flag.
    expect_errno(timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &armed, NULL),
                 EINVAL, "TFD_TIMER_CANCEL_ON_SET");
    expect_errno(timerfd_settime(fd, 1 << 5, &armed, NULL), EINVAL, "unknown settime flag");
    struct itimerspec invalid = spec(0, 0);
    invalid.it_value.tv_nsec = 1000000000L;
    expect_errno(timerfd_settime(fd, 0, &invalid, NULL), EINVAL, "invalid tv_nsec");
    expect_errno(timerfd_settime(fd, 0, NULL, NULL), EFAULT, "NULL new_value");

    uint64_t expirations;
    expect_errno(read(fd, &expirations, sizeof(expirations) - 1), EINVAL, "short read");
    expirations = 1;
    expect_errno(write(fd, &expirations, sizeof(expirations)), EINVAL, "write");

    int eventfd_fd = eventfd(0, 0);
    TEST_ASSERT(eventfd_fd >= 0, "eventfd");
    expect_errno(timerfd_settime(eventfd_fd, 0, &armed, NULL), EINVAL, "not a timerfd");
    struct itimerspec its;
    expect_errno(timerfd_gettime(eventfd_fd, &its), EINVAL, "gettime not a timerfd");
    TEST_ASSERT(close(eventfd_fd) == 0, "close eventfd");
    TEST_ASSERT(close(fd) == 0, "close");
    expect_errno(timerfd_gettime(fd, &its), EBADF, "closed timerfd");
}

int main(void) {
    test_one_shot();
    test_periodic();
    test_absolute(CLOCK_MONOTONIC);
    test_absolute(CLOCK_REALTIME);
    test_epoll();
    test_invalid_arguments();
    printf("timerfd tests passed\n");
    return 0;
}
