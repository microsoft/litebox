// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

static void expect(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
        exit(1);
    }
}

static void test_order(int flags) {
    int fds[2];
    expect(syscall(SYS_pipe2, fds, flags) == 0, "pipe2");
    expect(fds[0] < fds[1], "read end gets the lower descriptor");
    char value = 0;
    expect(write(fds[1], "x", 1) == 1, "write to higher descriptor");
    expect(read(fds[0], &value, 1) == 1 && value == 'x',
           "read from lower descriptor");
    expect(close(fds[0]) == 0 && close(fds[1]) == 0, "close pipe");
}

static void test_descriptor_holes(void) {
    int slots[3];
    for (int i = 0; i < 3; i++) {
        slots[i] = dup(STDOUT_FILENO);
        expect(slots[i] >= 0, "reserve descriptor");
    }
    expect(close(slots[0]) == 0 && close(slots[2]) == 0,
           "create descriptor holes");
    int fds[2];
    expect(syscall(SYS_pipe2, fds, 0) == 0, "pipe2 with descriptor holes");
    expect(fds[0] == slots[0] && fds[1] == slots[2],
           "allocate lowest free descriptor to read end first");
    expect(close(fds[0]) == 0 && close(fds[1]) == 0 && close(slots[1]) == 0,
           "close descriptors");
}

static void test_descriptor_exhaustion(void) {
    struct rlimit original;
    expect(getrlimit(RLIMIT_NOFILE, &original) == 0, "get descriptor limit");
    int lowest = dup(STDOUT_FILENO);
    expect(lowest >= 0, "find lowest free descriptor");
    expect(close(lowest) == 0, "release descriptor");

    struct rlimit limit = original;
    for (int available = 0; available <= 1; available++) {
        limit.rlim_cur = (rlim_t)lowest + available;
        expect(setrlimit(RLIMIT_NOFILE, &limit) == 0, "limit descriptors");
        int fds[2];
        errno = 0;
        expect(syscall(SYS_pipe2, fds, 0) == -1 && errno == EMFILE,
               "pipe2 needs two free descriptors");
        if (available == 1) {
            int fd = dup(STDOUT_FILENO);
            expect(fd == lowest, "failed pipe2 does not leak a descriptor");
            expect(close(fd) == 0, "close reused descriptor");
        }
    }
    expect(setrlimit(RLIMIT_NOFILE, &original) == 0, "restore descriptor limit");
    test_order(0);
}

int main(void) {
    puts("Testing pipe descriptor order");
    test_order(0);
    test_order(O_CLOEXEC | O_NONBLOCK);
    test_descriptor_holes();
    test_descriptor_exhaustion();
    puts("All pipe descriptor order tests passed.");
    return 0;
}
