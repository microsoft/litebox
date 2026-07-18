// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BLOCKING_TEST_DELAY_US 50000
#define OPERATION_TIMEOUT_SECONDS 2
#define THREAD_JOIN_TIMEOUT_SECONDS 2

struct io_thread_args {
    int fd;
    unsigned char value;
    int write;
    int result;
    atomic_int started;
    atomic_int completed;
};

static void *io_thread(void *arg) {
    struct io_thread_args *args = arg;
    unsigned char value = args->value;
    atomic_store_explicit(&args->started, 1, memory_order_release);
    ssize_t result = args->write ? write(args->fd, &value, 1)
                                 : read(args->fd, &value, 1);
    args->result = result == 1 && (args->write || value == args->value) ? 0 : 1;
    atomic_store_explicit(&args->completed, 1, memory_order_release);
    return NULL;
}

static int poll_events(int fd, short events, short expected) {
    struct pollfd poll_fd = {
        .fd = fd,
        .events = events,
    };
    int ready = poll(&poll_fd, 1, 0);
    return ready >= 0 && poll_fd.revents == expected ? 0 : 1;
}

static int join_thread(pthread_t thread, int wake_fd) {
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) == 0) {
        deadline.tv_sec += THREAD_JOIN_TIMEOUT_SECONDS;
        if (pthread_timedjoin_np(thread, NULL, &deadline) == 0) {
            return 0;
        }
    }
    close(wake_fd);
    _exit(1);
}

static int test_nonblocking_and_lifecycle(void) {
    int fds[2];
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) {
        return 1;
    }
    int read_status = fcntl(fds[0], F_GETFL);
    int write_status = fcntl(fds[1], F_GETFL);
    int read_descriptor_flags = fcntl(fds[0], F_GETFD);
    int write_descriptor_flags = fcntl(fds[1], F_GETFD);
    if (read_status < 0 || write_status < 0 || read_descriptor_flags < 0 ||
        write_descriptor_flags < 0 || (read_status & O_NONBLOCK) == 0 ||
        (write_status & O_NONBLOCK) == 0 ||
        (read_descriptor_flags & FD_CLOEXEC) == 0 ||
        (write_descriptor_flags & FD_CLOEXEC) == 0) {
        return 2;
    }
    if (poll_events(fds[0], POLLIN, 0) != 0 ||
        poll_events(fds[1], POLLOUT, POLLOUT) != 0) {
        return 3;
    }

    unsigned char data[3] = {1, 2, 3};
    unsigned char output[3] = {0};
    errno = 0;
    if (read(fds[1], output, 0) != -1 || errno != EBADF) {
        return 4;
    }
    errno = 0;
    if (write(fds[0], data, 0) != -1 || errno != EBADF) {
        return 4;
    }
    errno = 0;
    if (read(fds[0], output, sizeof(output)) != -1 || errno != EAGAIN) {
        return 5;
    }
    if (write(fds[1], data, sizeof(data)) != sizeof(data) ||
        poll_events(fds[0], POLLIN, POLLIN) != 0 ||
        read(fds[0], output, sizeof(output)) != sizeof(output) ||
        memcmp(data, output, sizeof(data)) != 0) {
        return 6;
    }

    int duplicate = dup(fds[1]);
    if (duplicate < 0 || close(fds[1]) != 0 ||
        write(duplicate, data, sizeof(data)) != sizeof(data) ||
        read(fds[0], output, sizeof(output)) != sizeof(output)) {
        return 7;
    }
    return close(duplicate) == 0 && close(fds[0]) == 0 ? 0 : 8;
}

static int test_blocking_read_wakeup(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        return 1;
    }
    struct io_thread_args args = {
        .fd = fds[0],
        .value = 42,
        .write = 0,
        .result = -1,
    };
    atomic_init(&args.started, 0);
    atomic_init(&args.completed, 0);
    pthread_t thread;
    if (pthread_create(&thread, NULL, io_thread, &args) != 0) {
        return 2;
    }
    alarm(OPERATION_TIMEOUT_SECONDS);
    while (!atomic_load_explicit(&args.started, memory_order_acquire)) {
        sched_yield();
    }
    alarm(0);
    usleep(BLOCKING_TEST_DELAY_US);
    if (atomic_load_explicit(&args.completed, memory_order_acquire)) {
        pthread_join(thread, NULL);
        return 3;
    }
    unsigned char value = 42;
    alarm(OPERATION_TIMEOUT_SECONDS);
    ssize_t wake_result = write(fds[1], &value, 1);
    alarm(0);
    int join_result = join_thread(thread, fds[1]);
    if (wake_result != 1 || join_result != 0 || args.result != 0) {
        return 3;
    }

    unsigned char input[65536];
    unsigned char output[65536];
    memset(input, 0x5a, sizeof(input));
    alarm(OPERATION_TIMEOUT_SECONDS);
    ssize_t large_write_result = write(fds[1], input, sizeof(input));
    alarm(0);
    if (large_write_result != sizeof(input)) {
        return 4;
    }
    size_t read_size = 0;
    alarm(OPERATION_TIMEOUT_SECONDS);
    while (read_size < sizeof(output)) {
        ssize_t size =
            read(fds[0], output + read_size, sizeof(output) - read_size);
        if (size <= 0) {
            return 5;
        }
        read_size += (size_t)size;
    }
    alarm(0);
    if (memcmp(input, output, sizeof(input)) != 0) {
        return 6;
    }
    return close(fds[0]) == 0 && close(fds[1]) == 0 ? 0 : 7;
}

static int test_blocking_write_wakeup(void) {
    int fds[2];
    if (pipe2(fds, O_NONBLOCK) != 0) {
        return 1;
    }
    unsigned char data[4096] = {0};
    size_t total_written = 0;
    ssize_t write_result;
    alarm(OPERATION_TIMEOUT_SECONDS);
    while ((write_result = write(fds[1], data, sizeof(data))) == sizeof(data)) {
        total_written += sizeof(data);
        if (total_written > 65536) {
            return 2;
        }
    }
    alarm(0);
    if (total_written != 65536 || write_result != -1 || errno != EAGAIN ||
        fcntl(fds[1], F_SETFL, 0) != 0) {
        return 2;
    }

    struct io_thread_args args = {
        .fd = fds[1],
        .value = 7,
        .write = 1,
        .result = -1,
    };
    atomic_init(&args.started, 0);
    atomic_init(&args.completed, 0);
    pthread_t thread;
    if (pthread_create(&thread, NULL, io_thread, &args) != 0) {
        return 3;
    }
    alarm(OPERATION_TIMEOUT_SECONDS);
    while (!atomic_load_explicit(&args.started, memory_order_acquire)) {
        sched_yield();
    }
    alarm(0);
    usleep(BLOCKING_TEST_DELAY_US);
    if (atomic_load_explicit(&args.completed, memory_order_acquire)) {
        pthread_join(thread, NULL);
        return 4;
    }
    unsigned char value;
    alarm(OPERATION_TIMEOUT_SECONDS);
    ssize_t wake_result = read(fds[0], &value, 1);
    alarm(0);
    int join_result = join_thread(thread, fds[0]);
    if (wake_result != 1 || join_result != 0 || args.result != 0) {
        return 4;
    }
    return close(fds[0]) == 0 && close(fds[1]) == 0 ? 0 : 5;
}

static int test_closed_peers(void) {
    int fds[2];
    unsigned char value = 1;
    if (pipe(fds) != 0 || close(fds[1]) != 0 ||
        poll_events(fds[0], POLLIN, POLLHUP) != 0 ||
        read(fds[0], &value, 1) != 0 || close(fds[0]) != 0) {
        return 1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR || pipe(fds) != 0 ||
        close(fds[0]) != 0 ||
        poll_events(fds[1], POLLOUT, POLLOUT | POLLERR) != 0) {
        return 2;
    }
    if (write(fds[1], &value, 0) != 0) {
        return 3;
    }
    errno = 0;
    if (write(fds[1], &value, 1) != -1 || errno != EPIPE) {
        return 4;
    }
    return close(fds[1]) == 0 ? 0 : 5;
}

int main(void) {
    int result = test_nonblocking_and_lifecycle();
    if (result != 0) {
        return 10 + result;
    }
    result = test_blocking_read_wakeup();
    if (result != 0) {
        return 20 + result;
    }
    result = test_blocking_write_wakeup();
    if (result != 0) {
        return 30 + result;
    }
    result = test_closed_peers();
    return result == 0 ? 0 : 40 + result;
}
