// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Booted as litebox.init: checks, as the guest user, that the root is
// writable: files and a directory in /tmp, a file of 64 MiB, and /guest.txt,
// the guest user's in rootfs.tar ("from rootfs.tar\n").

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL %s:%d: %s (errno %d: %s)\n", __FILE__, __LINE__,      \
                   #cond, errno, strerror(errno));                             \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static void write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, content, strlen(content)) == (ssize_t)strlen(content));
    CHECK(close(fd) == 0);
}

static void check_content(const char *path, const char *content) {
    char buffer[256];
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    ssize_t n = read(fd, buffer, sizeof(buffer));
    CHECK(n == (ssize_t)strlen(content) && memcmp(buffer, content, (size_t)n) == 0);
    CHECK(close(fd) == 0);
}

static void tmp(void) {
    write_file("/tmp/a", "first\n");
    check_content("/tmp/a", "first\n");
    CHECK(rename("/tmp/a", "/tmp/b") == 0);
    CHECK(access("/tmp/a", F_OK) == -1 && errno == ENOENT);
    check_content("/tmp/b", "first\n");
    int fd = open("/tmp/b", O_WRONLY | O_APPEND);
    CHECK(fd >= 0);
    CHECK(write(fd, "second\n", 7) == 7);
    CHECK(close(fd) == 0);
    check_content("/tmp/b", "first\nsecond\n");
    CHECK(mkdir("/tmp/d", 0755) == 0);
    CHECK(rename("/tmp/b", "/tmp/d/c") == 0);
    check_content("/tmp/d/c", "first\nsecond\n");
    CHECK(rmdir("/tmp/d") == -1 && errno == ENOTEMPTY);
    CHECK(unlink("/tmp/d/c") == 0);
    CHECK(rmdir("/tmp/d") == 0);
    CHECK(access("/tmp/d", F_OK) == -1 && errno == ENOENT);
    printf("/tmp: ok\n");
}

static void large(void) {
    int fd = open("/tmp/large", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    CHECK(ftruncate(fd, 64 << 20) == 0);
    CHECK(pwrite(fd, "x", 1, 64 << 20) == 1);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == (64 << 20) + 1);
    char c = 0;
    CHECK(pread(fd, &c, 1, 64 << 20) == 1 && c == 'x');
    CHECK(pread(fd, &c, 1, 32 << 20) == 1 && c == 0);
    CHECK(close(fd) == 0);
    CHECK(unlink("/tmp/large") == 0);
    printf("large: ok\n");
}

static void overwrite(void) {
    check_content("/guest.txt", "from rootfs.tar\n");
    write_file("/guest.txt", "overwritten\n");
    check_content("/guest.txt", "overwritten\n");
    printf("/guest.txt: ok\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    tmp();
    large();
    overwrite();
    return 0;
}
