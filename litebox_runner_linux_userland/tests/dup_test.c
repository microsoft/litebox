// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: dup, dup2, dup3 - file descriptor duplication
// Basic syscalls used by shell redirections and process management

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_dup_basic(void) {
    const char *path = "/tmp/dup_test";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    int newfd = dup(fd);
    TEST_ASSERT(newfd >= 0, "dup failed");
    TEST_ASSERT(newfd != fd, "dup should return different fd");

    // Write through both fds
    write(fd, "hello", 5);
    write(newfd, "world", 5);

    close(fd);
    close(newfd);

    // Verify
    fd = open(path, O_RDONLY);
    char buf[16] = {0};
    read(fd, buf, 10);
    close(fd);
    TEST_ASSERT(strcmp(buf, "helloworld") == 0, "dup should share file position");

    unlink(path);
    printf("dup basic: PASS\n");
    return 0;
}

int test_dup2_basic(void) {
    const char *path = "/tmp/dup2_test";
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    // dup2 to a specific fd number
    int target = 100;
    int result = dup2(fd, target);
    TEST_ASSERT(result == target, "dup2 should return target fd");

    // Write through new fd
    write(target, "test", 4);

    close(fd);
    close(target);

    // Verify
    fd = open(path, O_RDONLY);
    char buf[8] = {0};
    read(fd, buf, 4);
    close(fd);
    TEST_ASSERT(strcmp(buf, "test") == 0, "dup2 write failed");

    unlink(path);
    printf("dup2 basic: PASS\n");
    return 0;
}

int test_dup2_same_fd(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    // dup2 to same fd is a no-op (doesn't close)
    int result = dup2(pipefd[0], pipefd[0]);
    TEST_ASSERT(result == pipefd[0], "dup2 same fd should return same fd");

    // fd should still be valid
    char c = 'x';
    write(pipefd[1], &c, 1);
    char buf;
    ssize_t n = read(pipefd[0], &buf, 1);
    TEST_ASSERT(n == 1 && buf == 'x', "fd should still work after dup2 to itself");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("dup2 same fd: PASS\n");
    return 0;
}

int test_dup2_close_old(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    const char *path = "/tmp/dup2_close_test";
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    // dup2 should close the target fd first if it's open
    int result = dup2(pipefd[0], fd);
    TEST_ASSERT(result == fd, "dup2 should return target");

    // fd is now a dup of pipefd[0] (read end of pipe)
    // Reading through original pipe write end and our dup should work
    write(pipefd[1], "x", 1);
    char c;
    ssize_t n = read(fd, &c, 1);
    TEST_ASSERT(n == 1 && c == 'x', "fd should be readable pipe end now");

    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    unlink(path);
    printf("dup2 close old: PASS\n");
    return 0;
}

int test_dup3_cloexec(void) {
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe failed");

    int newfd = dup3(pipefd[0], 200, O_CLOEXEC);
    TEST_ASSERT(newfd == 200, "dup3 should return target fd");

    // Check O_CLOEXEC is set
    int flags = fcntl(newfd, F_GETFD);
    TEST_ASSERT(flags != -1, "fcntl F_GETFD failed");
    TEST_ASSERT(flags & FD_CLOEXEC, "O_CLOEXEC should be set");

    close(pipefd[0]);
    close(pipefd[1]);
    close(newfd);
    printf("dup3 O_CLOEXEC: PASS\n");
    return 0;
}

int test_dup_ebadf(void) {
    int result = dup(-1);
    TEST_ASSERT(result == -1 && errno == EBADF, "dup(-1) should return EBADF");

    result = dup(999);
    TEST_ASSERT(result == -1 && errno == EBADF, "dup(closed fd) should return EBADF");

    printf("dup EBADF: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting dup tests...\n");

    if (test_dup_basic() != 0) return 1;
    if (test_dup2_basic() != 0) return 1;
    if (test_dup2_same_fd() != 0) return 1;
    if (test_dup2_close_old() != 0) return 1;
    if (test_dup3_cloexec() != 0) return 1;
    if (test_dup_ebadf() != 0) return 1;

    printf("All dup tests passed!\n");
    return 0;
}
