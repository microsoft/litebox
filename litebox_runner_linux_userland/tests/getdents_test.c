// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: getdents64
// Directory reading at syscall level

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

int test_getdents64_root(void) {
    int fd = open("/", O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open / failed");

    char buf[4096];
    int nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
    TEST_ASSERT(nread > 0, "getdents64 failed");

    // Verify we got some entries
    int count = 0;
    int found_dot = 0;
    for (int pos = 0; pos < nread;) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
        count++;
        if (strcmp(d->d_name, ".") == 0) found_dot = 1;
        pos += d->d_reclen;
    }
    TEST_ASSERT(count > 0, "should have directory entries");
    TEST_ASSERT(found_dot, "should have . entry");

    close(fd);
    printf("getdents64 root: PASS\n");
    return 0;
}

int test_getdents64_tmp(void) {
    // Create a test directory with some files
    const char *testdir = "/tmp/getdents_test_dir";
    mkdir(testdir, 0755);

    char path[256];
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/file%d", testdir, i);
        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) close(fd);
    }

    int fd = open(testdir, O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open testdir failed");

    char buf[4096];
    int nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
    TEST_ASSERT(nread > 0, "getdents64 testdir failed");

    // Count entries
    int count = 0;
    for (int pos = 0; pos < nread;) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
        count++;
        pos += d->d_reclen;
    }
    // Should have at least ., .., and our 3 files
    TEST_ASSERT(count >= 5, "should have at least 5 entries");

    close(fd);

    // Cleanup
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/file%d", testdir, i);
        unlink(path);
    }
    rmdir(testdir);

    printf("getdents64 tmp: PASS\n");
    return 0;
}

int test_readdir(void) {
    DIR *dir = opendir("/");
    TEST_ASSERT(dir != NULL, "opendir / failed");

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        count++;
    }
    TEST_ASSERT(count > 0, "should have entries");

    closedir(dir);
    printf("readdir: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting getdents tests...\n");

    if (test_getdents64_root() != 0) return 1;
    if (test_getdents64_tmp() != 0) return 1;
    if (test_readdir() != 0) return 1;

    printf("All getdents tests passed!\n");
    return 0;
}
