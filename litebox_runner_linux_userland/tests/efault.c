// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define INVALID ((void *)0x10000)

static void expect_efault(ssize_t r, const char *operation) {
    if (r >= 0) {
        fprintf(stderr, "%s with an invalid address succeeded unexpectedly\n", operation);
        abort();
    }
    if (errno != EFAULT) {
        perror(operation);
        abort();
    }
}

int main() {
    expect_efault(write(STDOUT_FILENO, INVALID, 1), "write to stdout");

    const char *path = "/tmp/test_efault.bin";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    if (write(fd, "abcd", 4) != 4) {
        perror("write");
        return 1;
    }
    expect_efault(write(fd, INVALID, 4), "file write");
    expect_efault(pread(fd, INVALID, 4, 0), "file pread");
    struct stat status;
    if (fstat(fd, &status) != 0 || status.st_size != 4) {
        fprintf(stderr, "a faulting write changed the file\n");
        return 1;
    }
    char contents[4];
    if (pread(fd, contents, sizeof(contents), 0) != 4 || contents[0] != 'a' ||
        contents[3] != 'd') {
        fprintf(stderr, "the file lost its contents\n");
        return 1;
    }
    close(fd);
    unlink(path);
    return 0;
}
