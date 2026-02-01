// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: pread, pwrite - positional I/O
// Read/write at offset without changing file position

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

int test_pwrite_basic(void) {
    const char *path = "/tmp/pwrite_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    // Write at beginning
    write(fd, "AAAA", 4);

    // pwrite at offset 2 (shouldn't move position)
    ssize_t n = pwrite(fd, "XX", 2, 2);
    TEST_ASSERT(n == 2, "pwrite should write 2 bytes");

    // File position should still be at 4
    off_t pos = lseek(fd, 0, SEEK_CUR);
    TEST_ASSERT(pos == 4, "position should not change after pwrite");

    // Verify content
    lseek(fd, 0, SEEK_SET);
    char buf[8] = {0};
    read(fd, buf, 4);
    TEST_ASSERT(strcmp(buf, "AAXX") == 0, "content should be AAXX");

    close(fd);
    unlink(path);
    printf("pwrite basic: PASS\n");
    return 0;
}

int test_pread_basic(void) {
    const char *path = "/tmp/pread_test";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "0123456789", 10);

    // Position at start
    lseek(fd, 0, SEEK_SET);

    // pread from offset 5
    char buf[8] = {0};
    ssize_t n = pread(fd, buf, 4, 5);
    TEST_ASSERT(n == 4, "pread should read 4 bytes");
    TEST_ASSERT(strcmp(buf, "5678") == 0, "should read from offset");

    // Position should still be at 0
    off_t pos = lseek(fd, 0, SEEK_CUR);
    TEST_ASSERT(pos == 0, "position should not change after pread");

    close(fd);
    unlink(path);
    printf("pread basic: PASS\n");
    return 0;
}

int test_pwrite_extend(void) {
    const char *path = "/tmp/pwrite_extend";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "open failed");

    // pwrite beyond current file size
    ssize_t n = pwrite(fd, "END", 3, 10);
    TEST_ASSERT(n == 3, "pwrite should write 3 bytes");

    // File should be extended with zeros
    struct stat st;
    fstat(fd, &st);
    TEST_ASSERT(st.st_size == 13, "file size should be 13");

    // Read the hole (should be zeros)
    char buf[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    lseek(fd, 0, SEEK_SET);
    read(fd, buf, 13);
    for (int i = 0; i < 10; i++) {
        TEST_ASSERT(buf[i] == 0, "hole should be zeros");
    }
    TEST_ASSERT(memcmp(buf + 10, "END", 3) == 0, "end should have data");

    close(fd);
    unlink(path);
    printf("pwrite extend: PASS\n");
    return 0;
}

int test_pread_eof(void) {
    const char *path = "/tmp/pread_eof";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "short", 5);

    // pread beyond EOF
    char buf[8] = {0};
    ssize_t n = pread(fd, buf, 8, 10);
    TEST_ASSERT(n == 0, "pread beyond EOF should return 0");

    // pread partial at end
    n = pread(fd, buf, 8, 3);
    TEST_ASSERT(n == 2, "pread at end should return partial");
    TEST_ASSERT(memcmp(buf, "rt", 2) == 0, "should read last 2 bytes");

    close(fd);
    unlink(path);
    printf("pread EOF: PASS\n");
    return 0;
}

int test_pread_pwrite_concurrent(void) {
    const char *path = "/tmp/preadwrite_concurrent";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    write(fd, "ABCDEFGHIJ", 10);

    // Multiple pread/pwrite without affecting each other
    char buf1[4] = {0}, buf2[4] = {0};

    pread(fd, buf1, 3, 0);   // Read "ABC"
    pwrite(fd, "XXX", 3, 5); // Write at 5
    pread(fd, buf2, 3, 5);   // Read "XXX"

    TEST_ASSERT(strcmp(buf1, "ABC") == 0, "first read should be ABC");
    TEST_ASSERT(strcmp(buf2, "XXX") == 0, "second read should be XXX");

    close(fd);
    unlink(path);
    printf("pread/pwrite concurrent: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting pread/pwrite tests...\n");

    if (test_pwrite_basic() != 0) return 1;
    if (test_pread_basic() != 0) return 1;
    if (test_pwrite_extend() != 0) return 1;
    if (test_pread_eof() != 0) return 1;
    if (test_pread_pwrite_concurrent() != 0) return 1;

    printf("All pread/pwrite tests passed!\n");
    return 0;
}
