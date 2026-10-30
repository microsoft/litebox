// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

int main(void) {
    char path[] = "/tmp/lb_rename_XXXXXX";
    char buffer[5];
    struct stat st;

    TEST_ASSERT(mkdtemp(path) != NULL, "mkdtemp failed");
    TEST_ASSERT(chdir(path) == 0, "chdir tmpdir failed");
    int fd = open("source", O_CREAT | O_EXCL | O_RDWR, 0600);
    TEST_ASSERT(fd >= 0, "create source failed");
    TEST_ASSERT(write(fd, "hello", 5) == 5, "write source failed");

    TEST_ASSERT(rename("source", "moved") == 0, "rename file failed");
    errno = 0;
    TEST_ASSERT(stat("source", &st) == -1 && errno == ENOENT,
                "old name should no longer exist");
    create_test_file("target", 0600);
    TEST_ASSERT(renameat(AT_FDCWD, "moved", AT_FDCWD, "target") == 0,
                "renameat should replace an existing file");
    TEST_ASSERT(syscall(SYS_renameat2, AT_FDCWD, "target", AT_FDCWD, "final", 0) == 0,
                "renameat2 with zero flags failed");

    int renamed = open("final", O_RDONLY);
    TEST_ASSERT(renamed >= 0, "open renamed file failed");
    TEST_ASSERT(read(renamed, buffer, sizeof(buffer)) == 5,
                "read renamed file failed");
    TEST_ASSERT(memcmp(buffer, "hello", sizeof(buffer)) == 0,
                "renamed file contents changed");
    TEST_ASSERT(pread(fd, buffer, sizeof(buffer), 0) == 5,
                "original file descriptor should remain usable");
    TEST_ASSERT(memcmp(buffer, "hello", sizeof(buffer)) == 0,
                "original file descriptor contents changed");
    TEST_ASSERT(close(renamed) == 0 && close(fd) == 0, "close files failed");
    TEST_ASSERT(unlink("final") == 0, "cleanup file failed");

    TEST_ASSERT(mkdir("directory", 0700) == 0, "mkdir failed");
    TEST_ASSERT(rename("directory", "renamed_directory") == 0, "rename directory failed");
    TEST_ASSERT(stat("renamed_directory", &st) == 0 && S_ISDIR(st.st_mode),
                "renamed directory should exist");
    TEST_ASSERT(rmdir("renamed_directory") == 0, "cleanup directory failed");
    errno = 0;
    TEST_ASSERT(rename("missing", "final") == -1 && errno == ENOENT,
                "rename missing path should fail with ENOENT");

    TEST_ASSERT(chdir("/") == 0, "leave tmpdir failed");
    TEST_ASSERT(rmdir(path) == 0, "cleanup tmpdir failed");
    puts("All rename tests passed.");
    return 0;
}
