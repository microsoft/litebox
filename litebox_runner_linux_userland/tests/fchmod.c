// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void check_mode(int fd, mode_t mode) {
    struct stat status;
    assert(fstat(fd, &status) == 0);
    assert((status.st_mode & 07777) == mode);
}

static void check_directory(void) {
    assert(mkdir("/registry/fchmod-directory", 0700) == 0);
    int fd = open("/registry/fchmod-directory", O_RDONLY | O_DIRECTORY);
    assert(fd >= 0);
    assert(rename("/registry/fchmod-directory", "/registry/fchmod-directory-renamed") == 0);
    assert(mkdir("/registry/fchmod-directory", 0700) == 0);
    int replacement = open("/registry/fchmod-directory", O_RDONLY | O_DIRECTORY);
    assert(replacement >= 0);
    int result = fchmod(fd, 0500);
    if (result != 0) {
        perror("fchmod retained directory");
    }
    assert(result == 0);
    check_mode(fd, 0500);
    check_mode(replacement, 0700);
    assert(rmdir("/registry/fchmod-directory-renamed") == 0);
    assert(fchmod(fd, 0700) == 0);
    check_mode(fd, 0700);
    check_mode(replacement, 0700);
    assert(close(fd) == 0 && close(replacement) == 0);
    assert(rmdir("/registry/fchmod-directory") == 0);
}

int main(int argc, char **argv) {
    int local = argc > 1 && strcmp(argv[1], "local") == 0;
    if (argc > 1 && strcmp(argv[1], "read-only") == 0) {
        assert(argc == 3);
        int fd = open(argv[2], O_RDONLY);
        assert(fd >= 0);
        errno = 0;
        assert(fchmod(fd, 0600) == -1 && errno == EROFS);
        assert(close(fd) == 0);
        puts("fchmod: EROFS OK");
        return 0;
    }
    // The default fixture's writable registry is root-owned; the LocalFs mount is not.
    if (!local) {
        int directory = open("/registry", O_RDONLY | O_DIRECTORY);
        struct stat status;
        assert(directory >= 0 && fstat(directory, &status) == 0);
        assert(status.st_uid == 0 && geteuid() == 1000);
        errno = 0;
        assert(fchmod(directory, 0777) == -1 && errno == EPERM);
        assert(close(directory) == 0);
    }
    // The LocalFs fixture retains directory objects across rename and unlink.
    if (local) {
        check_directory();
    }
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
