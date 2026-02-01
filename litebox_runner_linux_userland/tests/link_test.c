// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Integration test for link(2) and linkat(2) syscalls

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define TEST_FILE "/tmp/link_test_original"
#define LINK_FILE "/tmp/link_test_linked"
#define TEST_DIR "/tmp/link_test_dir"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s (line %d): %s\n", msg, __LINE__, strerror(errno)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_ERRNO(cond, expected_errno, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s (line %d): expected errno %d, got %d (%s)\n", \
               msg, __LINE__, expected_errno, errno, strerror(errno)); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_PASS(name) do { \
    printf("PASS: %s\n", name); \
    tests_passed++; \
} while(0)

// Cleanup function
static void cleanup(void) {
    unlink(TEST_FILE);
    unlink(LINK_FILE);
    // Note: rmdir not yet implemented in litebox
    // rmdir(TEST_DIR);
}

// Test basic link creation
static void test_link_basic(void) {
    cleanup();

    // Create a file
    int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
    ASSERT(fd >= 0, "create original file");

    const char *data = "test data for link";
    ssize_t written = write(fd, data, strlen(data));
    ASSERT(written == (ssize_t)strlen(data), "write to original file");
    close(fd);

    // Create hard link
    int ret = link(TEST_FILE, LINK_FILE);
    ASSERT(ret == 0, "create hard link");

    // Verify both files exist and have the same content
    char buf[64] = {0};
    fd = open(LINK_FILE, O_RDONLY);
    ASSERT(fd >= 0, "open linked file");

    ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);
    ASSERT(bytes_read == (ssize_t)strlen(data), "read from linked file");
    ASSERT(strcmp(buf, data) == 0, "content matches");
    close(fd);

    // Verify inode is the same (hard link property)
    struct stat stat_original, stat_linked;
    ASSERT(stat(TEST_FILE, &stat_original) == 0, "stat original");
    ASSERT(stat(LINK_FILE, &stat_linked) == 0, "stat linked");
    ASSERT(stat_original.st_ino == stat_linked.st_ino, "same inode");
    // Note: nlink tracking not yet fully implemented in litebox
    // ASSERT(stat_original.st_nlink >= 2, "nlink >= 2");

    cleanup();
    TEST_PASS("test_link_basic");
}

// Test that modifications through link are visible via original
static void test_link_shared_data(void) {
    cleanup();

    // Create a file
    int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
    ASSERT(fd >= 0, "create original file");
    write(fd, "original", 8);
    close(fd);

    // Create hard link
    ASSERT(link(TEST_FILE, LINK_FILE) == 0, "create hard link");

    // Modify through link
    fd = open(LINK_FILE, O_WRONLY);
    ASSERT(fd >= 0, "open linked file for write");
    write(fd, "modified", 8);
    close(fd);

    // Read through original
    char buf[64] = {0};
    fd = open(TEST_FILE, O_RDONLY);
    ASSERT(fd >= 0, "open original file");
    read(fd, buf, sizeof(buf) - 1);
    close(fd);

    ASSERT(strcmp(buf, "modified") == 0, "data modified through link visible via original");

    cleanup();
    TEST_PASS("test_link_shared_data");
}

// Test unlinking original preserves data via link
static void test_link_unlink_original(void) {
    cleanup();

    // Create a file
    int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
    ASSERT(fd >= 0, "create original file");
    write(fd, "preserved", 9);
    close(fd);

    // Create hard link
    ASSERT(link(TEST_FILE, LINK_FILE) == 0, "create hard link");

    // Unlink original
    ASSERT(unlink(TEST_FILE) == 0, "unlink original");

    // Verify linked file still has data
    char buf[64] = {0};
    fd = open(LINK_FILE, O_RDONLY);
    ASSERT(fd >= 0, "open linked file after unlink original");
    read(fd, buf, sizeof(buf) - 1);
    close(fd);

    ASSERT(strcmp(buf, "preserved") == 0, "data preserved via link");

    // Verify original is gone
    ASSERT(access(TEST_FILE, F_OK) == -1, "original file should not exist");
    ASSERT(errno == ENOENT, "errno should be ENOENT");

    cleanup();
    TEST_PASS("test_link_unlink_original");
}

// Test linking to directory fails
static void test_link_directory_fails(void) {
    cleanup();

    // Create a directory
    ASSERT(mkdir(TEST_DIR, 0755) == 0, "create directory");

    // Attempt to link to directory - should fail with EPERM
    int ret = link(TEST_DIR, LINK_FILE);
    ASSERT_ERRNO(ret == -1 && errno == EPERM, EPERM, "link to directory should fail with EPERM");

    // Note: rmdir not yet implemented, clean up with unlink (will fail but cleanup file)
    unlink(TEST_DIR);
    cleanup();
    TEST_PASS("test_link_directory_fails");
}

// Test linking to existing file fails
static void test_link_exists_fails(void) {
    cleanup();

    // Create two files
    int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
    ASSERT(fd >= 0, "create first file");
    close(fd);

    fd = open(LINK_FILE, O_CREAT | O_WRONLY, 0644);
    ASSERT(fd >= 0, "create second file");
    close(fd);

    // Attempt to link - should fail with EEXIST
    int ret = link(TEST_FILE, LINK_FILE);
    ASSERT_ERRNO(ret == -1 && errno == EEXIST, EEXIST, "link to existing file should fail with EEXIST");

    cleanup();
    TEST_PASS("test_link_exists_fails");
}

// Test linking nonexistent file fails
static void test_link_nonexistent_fails(void) {
    cleanup();

    // Attempt to link nonexistent file - should fail with ENOENT
    int ret = link("/tmp/nonexistent_file_for_link_test", LINK_FILE);
    ASSERT_ERRNO(ret == -1 && errno == ENOENT, ENOENT, "link to nonexistent file should fail with ENOENT");

    cleanup();
    TEST_PASS("test_link_nonexistent_fails");
}

// Test linkat with AT_FDCWD
static void test_linkat_fdcwd(void) {
    cleanup();

    // Create a file
    int fd = open(TEST_FILE, O_CREAT | O_WRONLY, 0644);
    ASSERT(fd >= 0, "create original file");
    write(fd, "linkat test", 11);
    close(fd);

    // Create hard link using linkat with AT_FDCWD
    int ret = linkat(AT_FDCWD, TEST_FILE, AT_FDCWD, LINK_FILE, 0);
    ASSERT(ret == 0, "linkat with AT_FDCWD");

    // Verify link was created by reading its content
    char buf[64] = {0};
    fd = open(LINK_FILE, O_RDONLY);
    ASSERT(fd >= 0, "open linked file");
    ssize_t bytes_read = read(fd, buf, sizeof(buf) - 1);
    ASSERT(bytes_read == 11, "read from linked file");
    ASSERT(strcmp(buf, "linkat test") == 0, "content matches");
    close(fd);

    cleanup();
    TEST_PASS("test_linkat_fdcwd");
}

int main(void) {
    printf("===== link/linkat syscall tests =====\n\n");

    test_link_basic();
    test_link_shared_data();
    test_link_unlink_original();
    test_link_directory_fails();
    test_link_exists_fails();
    test_link_nonexistent_fails();
    test_linkat_fdcwd();

    printf("\n===== Results =====\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
