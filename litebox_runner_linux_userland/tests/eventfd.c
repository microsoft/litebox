// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/uio.h>
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

static int writev_values(int fd, uint64_t first, uint64_t second) {
    struct iovec iov[2] = {
        {&first, sizeof(first)},
        {&second, sizeof(second)},
    };
    return writev(fd, iov, 2) == (ssize_t)(sizeof(first) + sizeof(second)) ? 0 : 1;
}

static int readv_split_value(int fd, uint64_t expected) {
    uint8_t bytes[sizeof(expected)] = {0};
    struct iovec iov[2] = {
        {bytes, 4},
        {bytes + 4, 4},
    };
    uint64_t value = 0;
    if (readv(fd, iov, 2) != (ssize_t)sizeof(value)) {
        return 1;
    }
    memcpy(&value, bytes, sizeof(value));
    return value == expected ? 0 : 2;
}

static int expect_einval_short_readv(int fd) {
    uint32_t value = 0;
    struct iovec iov = {&value, sizeof(value)};
    errno = 0;
    if (readv(fd, &iov, 1) != -1) {
        return 1;
    }
    return errno == EINVAL ? 0 : 2;
}

static int expect_einval_split_writev(int fd) {
    uint32_t low = 1;
    uint32_t high = 0;
    struct iovec iov[2] = {
        {&low, sizeof(low)},
        {&high, sizeof(high)},
    };
    errno = 0;
    if (writev(fd, iov, 2) != -1) {
        return 1;
    }
    return errno == EINVAL ? 0 : 2;
}

int main(void) {
    int fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) {
        return 10;
    }
    if (expect_eagain_read(fd) != 0) {
        return 11;
    }
    if (write_value(fd, 3) != 0) {
        return 12;
    }
    if (read_value(fd, 3) != 0) {
        return 13;
    }
    if (writev_values(fd, 2, 5) != 0) {
        return 14;
    }
    if (read_value(fd, 7) != 0) {
        return 15;
    }
    if (write_value(fd, 9) != 0) {
        return 16;
    }
    if (readv_split_value(fd, 9) != 0) {
        return 17;
    }
    if (expect_einval_split_writev(fd) != 0) {
        return 18;
    }
    if (write_value(fd, 11) != 0) {
        return 19;
    }
    if (expect_einval_short_readv(fd) != 0) {
        return 20;
    }
    if (read_value(fd, 11) != 0) {
        return 21;
    }
    if (expect_eagain_read(fd) != 0) {
        return 22;
    }
    uint64_t invalid = UINT64_MAX;
    errno = 0;
    if (write(fd, &invalid, sizeof(invalid)) != -1 || errno != EINVAL) {
        return 23;
    }
    close(fd);

    int semaphore_fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    if (semaphore_fd < 0) {
        return 30;
    }
    if (write_value(semaphore_fd, 3) != 0) {
        return 31;
    }
    if (read_value(semaphore_fd, 1) != 0) {
        return 32;
    }
    if (read_value(semaphore_fd, 1) != 0) {
        return 33;
    }
    if (read_value(semaphore_fd, 1) != 0) {
        return 34;
    }
    if (expect_eagain_read(semaphore_fd) != 0) {
        return 35;
    }
    close(semaphore_fd);

    return 0;
}
