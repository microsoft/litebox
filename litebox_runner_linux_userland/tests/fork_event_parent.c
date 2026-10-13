// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that forked children share eventfds and timerfds with their parent.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Bounds every wait, so a failure cannot hang the test.
#define TIMEOUT_MS 30000

static int wait_readable(int fd) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    int ready;
    do {
        ready = poll(&poll_fd, 1, TIMEOUT_MS);
    } while (ready == -1 && errno == EINTR);
    return ready == 1;
}

static uint64_t read_count(int fd) {
    uint64_t value = 0;
    ssize_t n;
    do {
        n = read(fd, &value, sizeof(value));
    } while (n == -1 && errno == EINTR);
    return n == sizeof(value) ? value : 0;
}

static int write_count(int fd, uint64_t value) {
    return write(fd, &value, sizeof(value)) == sizeof(value);
}

// Returns whether `fd` is non-blocking and a read of it fails with `EAGAIN`. It reads only if
// `fd` is non-blocking, so it cannot block.
static int read_would_block(int fd) {
    int flags = fcntl(fd, F_GETFL);
    uint64_t value;
    return flags != -1 && (flags & O_NONBLOCK) != 0 && read(fd, &value, sizeof(value)) == -1 &&
           errno == EAGAIN;
}

static void sleep_ms(long ms) {
    struct timespec duration = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000};
    while (nanosleep(&duration, &duration) == -1 && errno == EINTR) {
    }
}

// Returns the exit code of `child`, first killing it unless `exiting`, or -1 if it did not exit
// normally.
static int reap(pid_t child, int exiting) {
    if (!exiting) {
        kill(child, SIGKILL);
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// A child blocked reading an eventfd wakes when its parent writes it, and its reply wakes the
// parent.
static int check_blocking_eventfd(void) {
    int request = eventfd(0, 0);
    int reply = eventfd(0, 0);
    if (request < 0 || reply < 0) {
        return 0;
    }
    pid_t child = fork();
    if (child == 0) {
        uint64_t value = read_count(request);
        _exit(value == 5 && write_count(reply, value + 1) ? 0 : 1);
    }
    if (child < 0) {
        return 0;
    }
    // Give the child time to block.
    sleep_ms(100);
    int ok = write_count(request, 5) && wait_readable(reply) && read_count(reply) == 6;
    ok &= reap(child, ok) == 0;
    close(request);
    close(reply);
    return ok;
}

// A semaphore eventfd keeps its mode and count in the child, and the status flags the child sets
// apply to the parent.
static int check_semaphore_eventfd(int *nonblock) {
    int fd = eventfd(2, EFD_SEMAPHORE | EFD_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    pid_t child = fork();
    if (child == 0) {
        int ok = read_count(fd) == 1 && fcntl(fd, F_SETFL, O_NONBLOCK) == 0;
        _exit(ok ? 0 : 1);
    }
    if (child < 0) {
        return 0;
    }
    int ok = reap(child, 1) == 0;
    int flags = fcntl(fd, F_GETFL);
    *nonblock = flags != -1 && (flags & O_NONBLOCK) != 0 && (flags & O_ACCMODE) == O_RDWR;
    // Reads only once the child has taken one of the two counts, so the read cannot block.
    ok = ok && read_count(fd) == 1;
    *nonblock &= read_would_block(fd);
    close(fd);
    return ok;
}

// A child blocked reading a timerfd its parent armed wakes when the timer expires, and consumes
// the expiration for the parent too.
static int check_timerfd(void) {
    int timer = timerfd_create(CLOCK_MONOTONIC, 0);
    int reply = eventfd(0, 0);
    if (timer < 0 || reply < 0) {
        return 0;
    }
    struct itimerspec spec = {.it_value = {.tv_nsec = 100000000}};
    if (timerfd_settime(timer, 0, &spec, NULL) != 0) {
        return 0;
    }
    pid_t child = fork();
    if (child == 0) {
        uint64_t expirations = read_count(timer);
        _exit(expirations == 1 && write_count(reply, 1) ? 0 : 1);
    }
    if (child < 0) {
        return 0;
    }
    int ok = wait_readable(reply) && read_count(reply) == 1;
    ok &= reap(child, ok) == 0;
    int on = 1;
    ok &= ioctl(timer, FIONBIO, &on) == 0 && read_would_block(timer);
    struct itimerspec current;
    ok &= timerfd_gettime(timer, &current) == 0 && current.it_value.tv_sec == 0 &&
          current.it_value.tv_nsec == 0;
    close(timer);
    close(reply);
    return ok;
}

int main(void) {
    int blocked = check_blocking_eventfd();
    int nonblock = 0;
    int semaphore = check_semaphore_eventfd(&nonblock);
    int timer = check_timerfd();
    printf("event-fork blocked=%d semaphore=%d nonblock=%d timer=%d\n", blocked, semaphore,
           nonblock, timer);
    return blocked && semaphore && nonblock && timer ? 0 : 1;
}
