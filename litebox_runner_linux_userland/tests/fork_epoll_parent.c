// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that forked children share epoll instances with their parent.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Bounds every wait, so a failure cannot hang the test.
#define TIMEOUT_MS 30000

static int epoll_wait_one(int epfd, int timeout_ms, uint64_t *data) {
    struct epoll_event event;
    int ready;
    do {
        ready = epoll_wait(epfd, &event, 1, timeout_ms);
    } while (ready == -1 && errno == EINTR);
    if (ready == 1) {
        *data = event.data.u64;
    }
    return ready;
}

static int epoll_add(int epfd, int fd, uint32_t events, uint64_t data) {
    struct epoll_event event = {.events = events, .data.u64 = data};
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) == 0;
}

static int write_count(int fd, uint64_t value) {
    return write(fd, &value, sizeof(value)) == sizeof(value);
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

// Interests a child adds or removes change the interest list of its parent.
static int check_shared_interests(void) {
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int fd = eventfd(0, 0);
    if (epfd < 0 || fd < 0) {
        return 0;
    }
    pid_t child = fork();
    if (child == 0) {
        _exit(epoll_add(epfd, fd, EPOLLIN, 7) ? 0 : 1);
    }
    if (child < 0) {
        return 0;
    }
    int ok = reap(child, 1) == 0;
    uint64_t data = 0;
    ok &= epoll_wait_one(epfd, 0, &data) == 0 && write_count(fd, 1) &&
          epoll_wait_one(epfd, 0, &data) == 1 && data == 7;

    child = fork();
    if (child == 0) {
        _exit(epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) == 0 ? 0 : 1);
    }
    if (child < 0) {
        return 0;
    }
    ok &= reap(child, 1) == 0;
    ok &= epoll_wait_one(epfd, 0, &data) == 0;
    ok &= epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) == -1 && errno == ENOENT;
    close(fd);
    close(epfd);
    return ok;
}

// A child blocked in `epoll_wait` wakes when its parent makes a watched object ready, and takes
// the edge-triggered event for the parent too.
static int check_blocking_wait(void) {
    int epfd = epoll_create1(0);
    int fd = eventfd(0, 0);
    if (epfd < 0 || fd < 0 || !epoll_add(epfd, fd, EPOLLIN | EPOLLET, 9)) {
        return 0;
    }
    pid_t child = fork();
    if (child == 0) {
        uint64_t data = 0;
        _exit(epoll_wait_one(epfd, TIMEOUT_MS, &data) == 1 && data == 9 ? 0 : 1);
    }
    if (child < 0) {
        return 0;
    }
    // Give the child time to block.
    sleep_ms(100);
    int ok = write_count(fd, 1);
    ok &= reap(child, ok) == 0;
    uint64_t data = 0;
    ok &= epoll_wait_one(epfd, 0, &data) == 0;
    close(fd);
    close(epfd);
    return ok;
}

// The status flags a child sets on an epoll instance apply to its parent.
static int check_status_flags(void) {
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        return 0;
    }
    pid_t child = fork();
    if (child == 0) {
        _exit(fcntl(epfd, F_SETFL, O_NONBLOCK) == 0 ? 0 : 1);
    }
    if (child < 0) {
        return 0;
    }
    int ok = reap(child, 1) == 0;
    int flags = fcntl(epfd, F_GETFL);
    ok &= flags != -1 && (flags & O_NONBLOCK) != 0 && (flags & O_ACCMODE) == O_RDWR;
    close(epfd);
    return ok;
}

int main(void) {
    int shared = check_shared_interests();
    int blocked = check_blocking_wait();
    int flags = check_status_flags();
    printf("epoll-fork shared=%d blocked=%d flags=%d\n", shared, blocked, flags);
    return shared && blocked && flags ? 0 : 1;
}
