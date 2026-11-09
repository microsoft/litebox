// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static void check_mode(int fd, mode_t mode) {
    struct stat status;
    assert(fstat(fd, &status) == 0);
    assert((status.st_mode & 07777) == mode);
}

int main(void) {
    int fd = open("/registry/fchmod-original", O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(fd >= 0);
    assert(write(fd, "data", 4) == 4);
    int read_only = open("/registry/fchmod-original", O_RDONLY);
    assert(read_only >= 0);
    int path_only = open("/registry/fchmod-original", O_PATH);
    assert(path_only >= 0);
    errno = 0;
    assert(fchmod(path_only, 0400) == -1 && errno == EBADF);
    assert(close(path_only) == 0);
    assert(rename("/registry/fchmod-original", "/registry/fchmod-renamed") == 0);
    int replacement = open("/registry/fchmod-original", O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(replacement >= 0);
    assert(fchmod(read_only, S_IFREG | 0500) == 0);
    check_mode(fd, 0500);
    check_mode(replacement, 0600);
    assert(unlink("/registry/fchmod-renamed") == 0);
    int duplicate = dup(read_only);
    assert(duplicate >= 0);
    assert(close(read_only) == 0);
    assert(fchmod(duplicate, 0200) == 0);
    check_mode(fd, 0200);
    check_mode(replacement, 0600);
    assert(fchmod(fd, 0) == 0);
    check_mode(duplicate, 0);
    assert(close(duplicate) == 0);
    assert(close(replacement) == 0);
    assert(close(fd) == 0);
    errno = 0;
    assert(fchmod(fd, 0600) == -1 && errno == EBADF);
    errno = 0;
    assert(fchmod(-1, 0600) == -1 && errno == EBADF);
    assert(unlink("/registry/fchmod-original") == 0);
    puts("fchmod: OK");
    return 0;
}
