// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int expect_eagain_read(int fd) {
    uint64_t value = 0;
    errno = 0;
    if (read(fd, &value, sizeof(value)) != -1) {
        return 1;
    }
    return errno == EAGAIN ? 0 : 2;
}

static int write_value(int fd, uint64_t value) {
    return write(fd, &value, sizeof(value)) == sizeof(value) ? 0 : 1;
}

static int read_value(int fd, uint64_t expected) {
    uint64_t value = 0;
    if (read(fd, &value, sizeof(value)) != sizeof(value)) {
        return 1;
    }
    return value == expected ? 0 : 2;
}

static int expect_poll_events(int fd, short expected) {
    struct pollfd poll_fd = {
        .fd = fd,
        .events = POLLIN | POLLOUT,
    };
    errno = 0;
    int ready = poll(&poll_fd, 1, 0);
    if (ready < 0) {
        return 1;
    }
    if ((poll_fd.revents & (POLLIN | POLLOUT)) != expected) {
        return 2;
    }
    return 0;
}

static int expect_eagain_write(int fd, uint64_t value) {
    errno = 0;
    if (write(fd, &value, sizeof(value)) != -1) {
        return 1;
    }
    return errno == EAGAIN ? 0 : 2;
}

static int clear_nonblock_with_ioctl(int fd) {
    int nonblock = 0;
    return ioctl(fd, FIONBIO, &nonblock) == 0 ? 0 : 1;
}

int main(void) {
    int fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) {
        return 10;
    }
    if (expect_poll_events(fd, POLLOUT) != 0) {
        return 11;
    }
    if (expect_eagain_read(fd) != 0) {
        return 12;
    }
    if (write_value(fd, 3) != 0) {
        return 13;
    }
    if (expect_poll_events(fd, POLLIN | POLLOUT) != 0) {
        return 14;
    }
    if (read_value(fd, 3) != 0) {
        return 15;
    }
    if (expect_poll_events(fd, POLLOUT) != 0) {
        return 16;
    }
    if (write_value(fd, 2) != 0) {
        return 17;
    }
    if (write_value(fd, 5) != 0) {
        return 18;
    }
    if (read_value(fd, 7) != 0) {
        return 19;
    }
    if (write_value(fd, 9) != 0) {
        return 20;
    }
    if (read_value(fd, 9) != 0) {
        return 21;
    }
    if (write_value(fd, 11) != 0) {
        return 22;
    }
    if (read_value(fd, 11) != 0) {
        return 23;
    }
    if (expect_eagain_read(fd) != 0) {
        return 24;
    }
    uint64_t invalid = UINT64_MAX;
    errno = 0;
    if (write(fd, &invalid, sizeof(invalid)) != -1 || errno != EINVAL) {
        return 25;
    }
    if (write_value(fd, UINT64_MAX - 1) != 0) {
        return 26;
    }
    if (expect_poll_events(fd, POLLIN) != 0) {
        return 27;
    }
    if (expect_eagain_write(fd, 1) != 0) {
        return 28;
    }
    if (read_value(fd, UINT64_MAX - 1) != 0) {
        return 29;
    }
    if (expect_poll_events(fd, POLLOUT) != 0) {
        return 30;
    }
    close(fd);

    int ioctl_toggle_fd = eventfd(1, EFD_NONBLOCK);
    if (ioctl_toggle_fd < 0) {
        return 31;
    }
    if (clear_nonblock_with_ioctl(ioctl_toggle_fd) != 0) {
        return 32;
    }
    if (read_value(ioctl_toggle_fd, 1) != 0) {
        return 33;
    }
    close(ioctl_toggle_fd);

    int semaphore_fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    if (semaphore_fd < 0) {
        return 40;
    }
    if (expect_poll_events(semaphore_fd, POLLOUT) != 0) {
        return 41;
    }
    if (write_value(semaphore_fd, 3) != 0) {
        return 42;
    }
    if (expect_poll_events(semaphore_fd, POLLIN | POLLOUT) != 0) {
        return 43;
    }
    if (read_value(semaphore_fd, 1) != 0) {
        return 44;
    }
    if (expect_poll_events(semaphore_fd, POLLIN | POLLOUT) != 0) {
        return 45;
    }
    if (read_value(semaphore_fd, 1) != 0) {
        return 46;
    }
    if (read_value(semaphore_fd, 1) != 0) {
        return 47;
    }
    if (expect_poll_events(semaphore_fd, POLLOUT) != 0) {
        return 48;
    }
    if (expect_eagain_read(semaphore_fd) != 0) {
        return 49;
    }
    close(semaphore_fd);

    return 0;
}
