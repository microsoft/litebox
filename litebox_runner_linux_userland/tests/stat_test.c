// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: stat, fstat, lstat
// File metadata operations
//
// Note: CodeQL flags TOCTOU race conditions in this file, but these are false
// positives since the tests run in LiteBox's sandboxed filesystem environment.
// lgtm[cpp/toctou-race-condition]

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_stat_file(void) {
    const char *path = "/tmp/stat_test_file";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");
    write(fd, "hello world", 11);
    close(fd);

    struct stat st;
    int ret = stat(path, &st);
    TEST_ASSERT(ret == 0, "stat failed");
    TEST_ASSERT(st.st_size == 11, "size should be 11");
    TEST_ASSERT(S_ISREG(st.st_mode), "should be regular file");
    TEST_ASSERT((st.st_mode & 0777) == 0644, "mode should be 0644");

    unlink(path);
    printf("stat file: PASS\n");
    return 0;
}

int test_fstat_file(void) {
    const char *path = "/tmp/fstat_test_file";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    TEST_ASSERT(fd >= 0, "open failed");
    write(fd, "test data", 9);

    struct stat st;
    int ret = fstat(fd, &st);
    TEST_ASSERT(ret == 0, "fstat failed");
    TEST_ASSERT(st.st_size == 9, "size should be 9");
    TEST_ASSERT(S_ISREG(st.st_mode), "should be regular file");

    close(fd);
    unlink(path);
    printf("fstat file: PASS\n");
    return 0;
}

int test_stat_directory(void) {
    struct stat st;
    int ret = stat("/tmp", &st);
    TEST_ASSERT(ret == 0, "stat /tmp failed");
    TEST_ASSERT(S_ISDIR(st.st_mode), "/tmp should be directory");

    printf("stat directory: PASS\n");
    return 0;
}

int test_fstat_pipe(void) {
    int pipefd[2];
    pipe(pipefd);

    struct stat st;
    int ret = fstat(pipefd[0], &st);
    TEST_ASSERT(ret == 0, "fstat pipe failed");
    TEST_ASSERT(S_ISFIFO(st.st_mode), "pipe should be FIFO");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("fstat pipe: PASS\n");
    return 0;
}

int test_stat_enoent(void) {
    struct stat st;
    int ret = stat("/nonexistent_file_12345", &st);
    TEST_ASSERT(ret == -1 && errno == ENOENT, "stat nonexistent should return ENOENT");

    printf("stat ENOENT: PASS\n");
    return 0;
}

int test_stat_size_changes(void) {
    const char *path = "/tmp/stat_size_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "initial", 7);

    struct stat st;
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 7, "initial size should be 7");

    // Append more data
    write(fd, " more", 5);
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 12, "size should be 12 after append");

    // Truncate
    ftruncate(fd, 5);
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 5, "size should be 5 after truncate");

    close(fd);
    unlink(path);
    printf("stat size changes: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting stat tests...\n");

    if (test_stat_file() != 0) return 1;
    if (test_fstat_file() != 0) return 1;
    if (test_stat_directory() != 0) return 1;
    if (test_fstat_pipe() != 0) return 1;
    if (test_stat_enoent() != 0) return 1;
    if (test_stat_size_changes() != 0) return 1;

    printf("All stat tests passed!\n");
    return 0;
}
