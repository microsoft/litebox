// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <sys/select.h>

static void check_readiness(int fd) {
    const short events[] = {POLLOUT, POLLIN, POLLIN | POLLOUT};
    for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
        struct pollfd pfd = {.fd = fd, .events = events[i]};
        TEST_ASSERT(poll(&pfd, 1, 0) == 1, "regular file must be immediately ready");
        TEST_ASSERT(pfd.revents == events[i], "poll must report all requested events");
    }

    fd_set readers, writers;
    FD_ZERO(&readers);
    FD_ZERO(&writers);
    FD_SET(fd, &readers);
    FD_SET(fd, &writers);
    struct timeval timeout = {0};
    TEST_ASSERT(select(fd + 1, &readers, &writers, NULL, &timeout) == 2,
                "select must report both read and write readiness");
    TEST_ASSERT(FD_ISSET(fd, &readers), "regular file must be readable");
    TEST_ASSERT(FD_ISSET(fd, &writers), "regular file must be writable");
}

int main(void) {
    char path[] = "/tmp/regular_file_readiness.XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    int reader = open(path, O_RDONLY);
    TEST_ASSERT(reader >= 0, "open read-only");
    int writer = open(path, O_WRONLY);
    TEST_ASSERT(writer >= 0, "open write-only");
    TEST_ASSERT(unlink(path) == 0, "unlink");

    // Linux reports readiness independently of file access mode and EOF.
    check_readiness(fd);
    check_readiness(reader);
    check_readiness(writer);

    TEST_ASSERT(write(fd, "x", 1) == 1, "write");
    TEST_ASSERT(lseek(fd, 0, SEEK_SET) == 0, "rewind");
    check_readiness(fd);
    char byte;
    TEST_ASSERT(read(fd, &byte, 1) == 1 && byte == 'x', "read data");
    TEST_ASSERT(read(fd, &byte, 1) == 0, "read EOF");
    check_readiness(fd);

    TEST_ASSERT(close(reader) == 0, "close reader");
    TEST_ASSERT(close(writer) == 0, "close writer");
    TEST_ASSERT(close(fd) == 0, "close");
    puts("regular file readiness: PASS");
    return 0;
}
