// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Self-validating timerfd exercise. The assertions encode native Linux
// semantics, so the same binary must exit 0 both when run natively (the gold
// standard) and under Litebox with a broker-backed timer. Each `return N`
// names a distinct failure so a non-zero exit pinpoints the phase.

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_SEC 1000000000L
#define NS_PER_MS 1000000L

static int arm_relative(int fd, long value_ns, long interval_ns) {
    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));
    spec.it_value.tv_sec = value_ns / NS_PER_SEC;
    spec.it_value.tv_nsec = value_ns % NS_PER_SEC;
    spec.it_interval.tv_sec = interval_ns / NS_PER_SEC;
    spec.it_interval.tv_nsec = interval_ns % NS_PER_SEC;
    return timerfd_settime(fd, 0, &spec, NULL);
}

static int disarm(int fd) {
    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));
    return timerfd_settime(fd, 0, &spec, NULL);
}

static int expect_eagain_read(int fd) {
    uint64_t value = 0;
    errno = 0;
    if (read(fd, &value, sizeof(value)) != -1) {
        return 1;
    }
    return errno == EAGAIN ? 0 : 2;
}

static int read_count(int fd, uint64_t *out) {
    uint64_t value = 0;
    if (read(fd, &value, sizeof(value)) != (ssize_t)sizeof(value)) {
        return 1;
    }
    *out = value;
    return 0;
}

static int poll_in(int fd, int timeout_ms) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    if (poll(&poll_fd, 1, timeout_ms) != 1) {
        return 1;
    }
    return (poll_fd.revents & POLLIN) ? 0 : 2;
}

// Phase 1: one-shot create, arm, gettime, poll, drain exactly one, disarm.
static int test_one_shot(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        return 1;
    }
    if (expect_eagain_read(fd) != 0) {
        return 2;
    }
    if (arm_relative(fd, 20 * NS_PER_MS, 0) != 0) {
        return 3;
    }
    struct itimerspec current;
    memset(&current, 0, sizeof(current));
    if (timerfd_gettime(fd, &current) != 0) {
        return 4;
    }
    if (current.it_value.tv_sec == 0 && current.it_value.tv_nsec == 0) {
        return 5;
    }
    if (poll_in(fd, 1000) != 0) {
        return 6;
    }
    uint64_t count = 0;
    if (read_count(fd, &count) != 0 || count != 1) {
        return 7;
    }
    if (expect_eagain_read(fd) != 0) {
        return 8;
    }
    if (arm_relative(fd, 20 * NS_PER_MS, 0) != 0) {
        return 9;
    }
    if (disarm(fd) != 0) {
        return 10;
    }
    if (timerfd_gettime(fd, &current) != 0) {
        return 11;
    }
    if (current.it_value.tv_sec != 0 || current.it_value.tv_nsec != 0) {
        return 12;
    }
    return close(fd) == 0 ? 0 : 13;
}

// Phase 2: an interval timer fires repeatedly.
static int test_interval(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        return 1;
    }
    if (arm_relative(fd, 10 * NS_PER_MS, 10 * NS_PER_MS) != 0) {
        return 2;
    }
    uint64_t total = 0;
    for (int i = 0; i < 2; i++) {
        if (poll_in(fd, 1000) != 0) {
            return 3;
        }
        uint64_t count = 0;
        if (read_count(fd, &count) != 0 || count < 1) {
            return 4;
        }
        total += count;
    }
    if (total < 2) {
        return 5;
    }
    if (disarm(fd) != 0) {
        return 6;
    }
    return close(fd) == 0 ? 0 : 7;
}

// Phase 3: an out-of-range itimerspec is rejected with EINVAL.
static int test_invalid_argument(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        return 1;
    }
    struct itimerspec bad;
    memset(&bad, 0, sizeof(bad));
    bad.it_value.tv_sec = 1;
    bad.it_value.tv_nsec = NS_PER_SEC; // must be < 1e9
    errno = 0;
    if (timerfd_settime(fd, 0, &bad, NULL) != -1 || errno != EINVAL) {
        return 2;
    }
    memset(&bad, 0, sizeof(bad));
    bad.it_value.tv_sec = 1;
    bad.it_interval.tv_nsec = 2 * NS_PER_SEC;
    errno = 0;
    if (timerfd_settime(fd, 0, &bad, NULL) != -1 || errno != EINVAL) {
        return 3;
    }
    return close(fd) == 0 ? 0 : 4;
}

// Phase 4: an unknown clock is rejected with EINVAL and creates no object.
static int test_invalid_clock(void) {
    errno = 0;
    if (timerfd_create(99, 0) != -1 || errno != EINVAL) {
        return 1;
    }
    return 0;
}

// Phase 5: TFD_CLOEXEC is reflected by F_GETFD.
static int test_cloexec(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (fd < 0) {
        return 1;
    }
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0) {
        return 2;
    }
    return close(fd) == 0 ? 0 : 3;
}

// Phase 6: O_NONBLOCK can be toggled with fcntl.
static int test_nonblock_toggle(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (fd < 0) {
        return 1;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_NONBLOCK) != 0) {
        return 2;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return 3;
    }
    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_NONBLOCK) == 0) {
        return 4;
    }
    if (expect_eagain_read(fd) != 0) {
        return 5;
    }
    return close(fd) == 0 ? 0 : 6;
}

// Phase 7: a dup shares the underlying timer and outlives the original fd.
static int test_dup_shares_timer(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        return 1;
    }
    int dup_fd = dup(fd);
    if (dup_fd < 0) {
        return 2;
    }
    if (arm_relative(fd, 15 * NS_PER_MS, 0) != 0) {
        return 3;
    }
    if (poll_in(dup_fd, 1000) != 0) {
        return 4;
    }
    uint64_t count = 0;
    if (read_count(dup_fd, &count) != 0 || count != 1) {
        return 5;
    }
    if (close(fd) != 0) {
        return 6;
    }
    if (arm_relative(dup_fd, 15 * NS_PER_MS, 0) != 0) {
        return 7;
    }
    if (poll_in(dup_fd, 1000) != 0) {
        return 8;
    }
    if (read_count(dup_fd, &count) != 0 || count != 1) {
        return 9;
    }
    return close(dup_fd) == 0 ? 0 : 10;
}

// Phase 8: an armed timer wakes epoll.
static int test_epoll_wakeup(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        return 1;
    }
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        return 2;
    }
    struct epoll_event event = {.events = EPOLLIN, .data.fd = fd};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
        return 3;
    }
    if (arm_relative(fd, 15 * NS_PER_MS, 0) != 0) {
        return 4;
    }
    struct epoll_event ready;
    if (epoll_wait(epoll_fd, &ready, 1, 1000) != 1) {
        return 5;
    }
    if ((ready.events & EPOLLIN) == 0 || ready.data.fd != fd) {
        return 6;
    }
    uint64_t count = 0;
    if (read_count(fd, &count) != 0 || count != 1) {
        return 7;
    }
    if (close(epoll_fd) != 0) {
        return 8;
    }
    return close(fd) == 0 ? 0 : 9;
}

// Phase 9: a blocking read parks until the timer expires.
static int test_blocking_read(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (fd < 0) {
        return 1;
    }
    if (arm_relative(fd, 20 * NS_PER_MS, 0) != 0) {
        return 2;
    }
    uint64_t count = 0;
    if (read_count(fd, &count) != 0 || count != 1) {
        return 3;
    }
    return close(fd) == 0 ? 0 : 4;
}

int main(void) {
    alarm(30);

    if (test_one_shot() != 0) {
        return 10;
    }
    if (test_interval() != 0) {
        return 20;
    }
    if (test_invalid_argument() != 0) {
        return 30;
    }
    if (test_invalid_clock() != 0) {
        return 40;
    }
    if (test_cloexec() != 0) {
        return 50;
    }
    if (test_nonblock_toggle() != 0) {
        return 60;
    }
    if (test_dup_shares_timer() != 0) {
        return 70;
    }
    if (test_epoll_wakeup() != 0) {
        return 80;
    }
    if (test_blocking_read() != 0) {
        return 90;
    }

    alarm(0);
    return 0;
}
