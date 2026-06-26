// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <fcntl.h>
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

static int expect_ebadf_read(int fd) {
    uint64_t value = 0;
    errno = 0;
    if (read(fd, &value, sizeof(value)) != -1) {
        return 1;
    }
    return errno == EBADF ? 0 : 2;
}

static int write_value(int fd, uint64_t value) {
    return write(fd, &value, sizeof(value)) == sizeof(value) ? 0 : 1;
}

static int expect_ebadf_write(int fd, uint64_t value) {
    errno = 0;
    if (write(fd, &value, sizeof(value)) != -1) {
        return 1;
    }
    return errno == EBADF ? 0 : 2;
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

static int expect_nonblock(int fd, int expected) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        return 1;
    }
    return ((flags & O_NONBLOCK) != 0) == expected ? 0 : 2;
}

static int expect_ebadf_close(int fd) {
    errno = 0;
    if (close(fd) != -1) {
        return 1;
    }
    return errno == EBADF ? 0 : 2;
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

    int dup_source_fd = eventfd(0, EFD_NONBLOCK);
    if (dup_source_fd < 0) {
        return 60;
    }
    int dup_fd = dup(dup_source_fd);
    if (dup_fd < 0) {
        return 61;
    }
    if (write_value(dup_source_fd, 7) != 0) {
        return 62;
    }
    if (read_value(dup_fd, 7) != 0) {
        return 63;
    }
    close(dup_source_fd);
    if (expect_ebadf_write(dup_source_fd, 1) != 0) {
        return 64;
    }
    if (write_value(dup_fd, 3) != 0) {
        return 65;
    }
    if (read_value(dup_fd, 3) != 0) {
        return 66;
    }
    close(dup_fd);
    if (expect_ebadf_close(dup_fd) != 0) {
        return 67;
    }
    if (expect_ebadf_read(dup_fd) != 0) {
        return 68;
    }

    int close_original_fd = eventfd(0, EFD_NONBLOCK);
    if (close_original_fd < 0) {
        return 70;
    }
    int close_dup_fd = dup(close_original_fd);
    if (close_dup_fd < 0) {
        return 71;
    }
    close(close_dup_fd);
    if (write_value(close_original_fd, 5) != 0) {
        return 72;
    }
    if (read_value(close_original_fd, 5) != 0) {
        return 73;
    }
    close(close_original_fd);

    int dup2_source_fd = eventfd(0, EFD_NONBLOCK);
    int dup2_replaced_fd = eventfd(0, EFD_NONBLOCK);
    if (dup2_source_fd < 0 || dup2_replaced_fd < 0) {
        return 80;
    }
    if (dup2(dup2_source_fd, dup2_replaced_fd) != dup2_replaced_fd) {
        return 81;
    }
    close(dup2_source_fd);
    if (write_value(dup2_replaced_fd, 11) != 0) {
        return 82;
    }
    if (read_value(dup2_replaced_fd, 11) != 0) {
        return 83;
    }
    close(dup2_replaced_fd);

    int status_fd = eventfd(0, EFD_NONBLOCK);
    if (status_fd < 0) {
        return 100;
    }
    int status_dup_fd = dup(status_fd);
    if (status_dup_fd < 0) {
        return 101;
    }
    if (expect_nonblock(status_fd, 1) != 0 || expect_nonblock(status_dup_fd, 1) != 0) {
        return 102;
    }
    if (fcntl(status_dup_fd, F_SETFL, 0) != 0) {
        return 103;
    }
    if (expect_nonblock(status_fd, 0) != 0 || expect_nonblock(status_dup_fd, 0) != 0) {
        return 104;
    }
    if (expect_eagain_read(status_fd) != 0) {
        return 105;
    }
    if (fcntl(status_fd, F_SETFL, O_NONBLOCK) != 0) {
        return 106;
    }
    if (expect_nonblock(status_fd, 1) != 0 || expect_nonblock(status_dup_fd, 1) != 0) {
        return 107;
    }
    close(status_fd);
    close(status_dup_fd);

    return 0;
}
