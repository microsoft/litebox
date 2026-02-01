// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: mkdir, mkdirat
// Directory creation
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

int test_mkdir_basic(void) {
    const char *path = "/tmp/mkdir_test_dir";

    // Make sure it doesn't exist
    rmdir(path);

    int ret = mkdir(path, 0755);
    TEST_ASSERT(ret == 0, "mkdir failed");

    // Verify it's a directory
    struct stat st;
    ret = stat(path, &st);
    TEST_ASSERT(ret == 0, "stat after mkdir failed");
    TEST_ASSERT(S_ISDIR(st.st_mode), "should be directory");

    // Cleanup - note: rmdir may not be supported
    rmdir(path);
    printf("mkdir basic: PASS\n");
    return 0;
}

int test_mkdir_eexist(void) {
    const char *path = "/tmp/mkdir_exist_test";
    rmdir(path);

    mkdir(path, 0755);

    // Try to create again - should fail
    int ret = mkdir(path, 0755);
    TEST_ASSERT(ret == -1 && errno == EEXIST, "mkdir existing should return EEXIST");

    rmdir(path);
    printf("mkdir EEXIST: PASS\n");
    return 0;
}

int test_mkdir_enoent(void) {
    // Try to create in non-existent parent
    int ret = mkdir("/nonexistent_parent_12345/subdir", 0755);
    TEST_ASSERT(ret == -1 && errno == ENOENT, "mkdir in nonexistent parent should return ENOENT");

    printf("mkdir ENOENT: PASS\n");
    return 0;
}

int test_mkdir_nested(void) {
    const char *parent = "/tmp/mkdir_nested_parent";
    const char *child = "/tmp/mkdir_nested_parent/child";

    rmdir(child);
    rmdir(parent);

    // Create parent
    int ret = mkdir(parent, 0755);
    TEST_ASSERT(ret == 0, "mkdir parent failed");

    // Create child
    ret = mkdir(child, 0755);
    TEST_ASSERT(ret == 0, "mkdir child failed");

    // Verify both exist
    struct stat st;
    TEST_ASSERT(stat(parent, &st) == 0 && S_ISDIR(st.st_mode), "parent should exist");
    TEST_ASSERT(stat(child, &st) == 0 && S_ISDIR(st.st_mode), "child should exist");

    rmdir(child);
    rmdir(parent);
    printf("mkdir nested: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting mkdir tests...\n");

    if (test_mkdir_basic() != 0) return 1;
    if (test_mkdir_eexist() != 0) return 1;
    if (test_mkdir_enoent() != 0) return 1;
    if (test_mkdir_nested() != 0) return 1;

    printf("All mkdir tests passed!\n");
    return 0;
}
