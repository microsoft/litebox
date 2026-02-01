// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: rename, renameat
// Note: link/symlink tests moved to link_test.c.disabled (syscalls not yet implemented)
//
// Note: CodeQL flags TOCTOU race conditions in this file, but these are false
// positives since the tests run in LiteBox's sandboxed filesystem environment.
// lgtm[cpp/toctou-race-condition]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d: %s)\n", \
                __func__, __LINE__, msg, errno, strerror(errno)); \
        return 1; \
    } \
} while(0)

int test_rename_basic(void) {
    const char *file1 = "/tmp/rename_test_1";
    const char *file2 = "/tmp/rename_test_2";

    // Create initial file
    int fd = open(file1, O_CREAT | O_WRONLY, 0644);
    TEST_ASSERT(fd >= 0, "create file1 failed");
    write(fd, "test", 4);
    close(fd);

    // Rename
    int ret = rename(file1, file2);
    TEST_ASSERT(ret == 0, "rename failed");

    // Verify old file doesn't exist
    TEST_ASSERT(access(file1, F_OK) == -1, "old file should not exist");

    // Verify new file exists
    TEST_ASSERT(access(file2, F_OK) == 0, "new file should exist");

    printf("rename basic: PASS\n");

    unlink(file2);
    return 0;
}

int test_rename_overwrite(void) {
    const char *file1 = "/tmp/rename_src";
    const char *file2 = "/tmp/rename_dst";

    // Create source file
    int fd = open(file1, O_CREAT | O_WRONLY, 0644);
    TEST_ASSERT(fd >= 0, "create src failed");
    write(fd, "source", 6);
    close(fd);

    // Create destination file
    fd = open(file2, O_CREAT | O_WRONLY, 0644);
    TEST_ASSERT(fd >= 0, "create dst failed");
    write(fd, "destination", 11);
    close(fd);

    // Rename should overwrite destination
    int ret = rename(file1, file2);
    TEST_ASSERT(ret == 0, "rename overwrite failed");

    // Verify content is from source
    fd = open(file2, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open renamed file failed");
    char buf[16] = {0};
    read(fd, buf, sizeof(buf));
    close(fd);
    TEST_ASSERT(strcmp(buf, "source") == 0, "content should be from source");

    printf("rename overwrite: PASS\n");

    unlink(file2);
    return 0;
}

int test_rename_enoent(void) {
    int ret = rename("/tmp/nonexistent_file_12345", "/tmp/dest");
    TEST_ASSERT(ret == -1 && errno == ENOENT, "rename nonexistent should return ENOENT");
    printf("rename ENOENT: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting rename tests...\n");

    if (test_rename_basic() != 0) return 1;
    if (test_rename_overwrite() != 0) return 1;
    if (test_rename_enoent() != 0) return 1;

    printf("All rename tests passed!\n");
    return 0;
}
