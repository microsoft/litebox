// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: lseek - file seek operations
// Basic file positioning

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

int test_lseek_set(void) {
    const char *path = "/tmp/lseek_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    write(fd, "0123456789", 10);

    // Seek to beginning
    off_t pos = lseek(fd, 0, SEEK_SET);
    TEST_ASSERT(pos == 0, "SEEK_SET to 0 failed");

    // Read and verify
    char c;
    read(fd, &c, 1);
    TEST_ASSERT(c == '0', "should read '0' after seek to start");

    // Seek to position 5
    pos = lseek(fd, 5, SEEK_SET);
    TEST_ASSERT(pos == 5, "SEEK_SET to 5 failed");

    read(fd, &c, 1);
    TEST_ASSERT(c == '5', "should read '5' after seek");

    close(fd);
    unlink(path);
    printf("lseek SEEK_SET: PASS\n");
    return 0;
}

int test_lseek_cur(void) {
    const char *path = "/tmp/lseek_cur_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "ABCDEFGHIJ", 10);
    lseek(fd, 0, SEEK_SET);

    // Read 3 bytes, position now at 3
    char buf[4];
    read(fd, buf, 3);

    // Seek forward 2 from current
    off_t pos = lseek(fd, 2, SEEK_CUR);
    TEST_ASSERT(pos == 5, "SEEK_CUR +2 from 3 should be 5");

    // Seek backward 1 from current
    pos = lseek(fd, -1, SEEK_CUR);
    TEST_ASSERT(pos == 4, "SEEK_CUR -1 from 5 should be 4");

    char c;
    read(fd, &c, 1);
    TEST_ASSERT(c == 'E', "should read 'E' at position 4");

    close(fd);
    unlink(path);
    printf("lseek SEEK_CUR: PASS\n");
    return 0;
}

int test_lseek_end(void) {
    const char *path = "/tmp/lseek_end_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "12345", 5);

    // Seek to end
    off_t pos = lseek(fd, 0, SEEK_END);
    TEST_ASSERT(pos == 5, "SEEK_END should be at 5");

    // Seek 2 before end
    pos = lseek(fd, -2, SEEK_END);
    TEST_ASSERT(pos == 3, "SEEK_END -2 should be 3");

    char c;
    read(fd, &c, 1);
    TEST_ASSERT(c == '4', "should read '4' at position 3");

    close(fd);
    unlink(path);
    printf("lseek SEEK_END: PASS\n");
    return 0;
}

int test_lseek_beyond_eof(void) {
    const char *path = "/tmp/lseek_beyond";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "ABC", 3);

    // Seek beyond EOF
    off_t pos = lseek(fd, 10, SEEK_SET);
    TEST_ASSERT(pos == 10, "should be able to seek beyond EOF");

    // Write at that position - creates a hole
    write(fd, "X", 1);

    // File should now be 11 bytes
    struct stat st;
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 11, "file size should be 11");

    close(fd);
    unlink(path);
    printf("lseek beyond EOF: PASS\n");
    return 0;
}

int test_lseek_pipe_fails(void) {
    int pipefd[2];
    pipe(pipefd);

    // lseek on pipe should fail with ESPIPE
    off_t pos = lseek(pipefd[0], 0, SEEK_SET);
    TEST_ASSERT(pos == -1 && errno == ESPIPE, "lseek on pipe should return ESPIPE");

    close(pipefd[0]);
    close(pipefd[1]);
    printf("lseek pipe ESPIPE: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting lseek tests...\n");

    if (test_lseek_set() != 0) return 1;
    if (test_lseek_cur() != 0) return 1;
    if (test_lseek_end() != 0) return 1;
    if (test_lseek_beyond_eof() != 0) return 1;
    if (test_lseek_pipe_fails() != 0) return 1;

    printf("All lseek tests passed!\n");
    return 0;
}
